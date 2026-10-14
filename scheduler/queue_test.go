package scheduler

import (
	"errors"
	"math/rand"
	"testing"

	"bfp/protocol"
)

func TestWeightedByteServiceAndNoStarvation(t *testing.T) {
	q := New[int](100, 1000000)
	classes := []protocol.Class{protocol.Interactive, protocol.Normal, protocol.Bulk}
	for flow, class := range classes {
		for i := 0; i < 1000; i++ {
			if err := q.Push(uint64(flow), class, 100, flow); err != nil {
				t.Fatal(err)
			}
		}
	}
	counts := [3]int{}
	last := [3]int{-1, -1, -1}
	for i := 0; i < 700; i++ {
		flow, ok := q.Pop()
		if !ok {
			t.Fatal("queue exhausted early")
		}
		counts[flow]++
		if last[flow] >= 0 && i-last[flow] > 7 {
			t.Fatalf("flow %d starved for %d dispatches", flow, i-last[flow])
		}
		last[flow] = i
	}
	if counts != [3]int{400, 200, 100} {
		t.Fatalf("expected 4:2:1 bytes, got %v", counts)
	}
}

func TestFIFOAndBudget(t *testing.T) {
	q := New[string](4, 10)
	if err := q.Push(10, protocol.Bulk, 6, "first"); err != nil {
		t.Fatal(err)
	}
	if err := q.Push(10, protocol.Interactive, 4, "second"); err != nil {
		t.Fatal(err)
	}
	if q.Len() != 2 || q.Bytes() != 10 {
		t.Fatalf("budget: %d %d", q.Len(), q.Bytes())
	}
	if err := q.Push(20, protocol.Normal, 1, "rejected"); !errors.Is(err, ErrFull) {
		t.Fatal(err)
	}
	if q.Len() != 2 || q.Bytes() != 10 {
		t.Fatal("rejection mutated queue")
	}
	for _, want := range []string{"first", "second"} {
		got, ok := q.Pop()
		if !ok || got != want {
			t.Fatalf("FIFO got %q want %q", got, want)
		}
	}
	if q.Len() != 0 || q.Bytes() != 0 || len(q.flows) != 0 || len(q.ring) != 0 {
		t.Fatal("empty queue retained state")
	}
	if _, ok := q.Pop(); ok {
		t.Fatal("empty queue returned value")
	}
	if err := q.Push(10, protocol.Normal, 10, "reused"); err != nil {
		t.Fatal(err)
	}
	if got, ok := q.Pop(); !ok || got != "reused" {
		t.Fatal("flow reuse failed")
	}
}

func TestInvalidCostsAndClasses(t *testing.T) {
	q := New[int](1, 10)
	for _, cost := range []int{0, -1} {
		if err := q.Push(1, protocol.Normal, cost, 0); !errors.Is(err, ErrCost) {
			t.Fatalf("cost %d: %v", cost, err)
		}
	}
	if err := q.Push(1, protocol.Class(255), 1, 0); !errors.Is(err, ErrClass) {
		t.Fatal(err)
	}
	if err := q.Push(1, protocol.Normal, int(^uint(0)>>1), 0); !errors.Is(err, ErrFull) {
		t.Fatal(err)
	}
	if q.Len() != 0 || q.Bytes() != 0 {
		t.Fatal("invalid push changed accounting")
	}
}

func TestLargeHeadTinyQuantumDoesNotBlockOtherFlows(t *testing.T) {
	q := New[int](1, 20000000)
	if err := q.Push(1, protocol.Bulk, 10000000, 1); err != nil {
		t.Fatal(err)
	}
	if err := q.Push(2, protocol.Bulk, 1, 2); err != nil {
		t.Fatal(err)
	}
	if got, ok := q.Pop(); !ok || got != 2 {
		t.Fatal("large head blocked runnable other flow")
	}
	if got, ok := q.Pop(); !ok || got != 1 {
		t.Fatal("large head did not eventually receive service")
	}
}

func TestUnequalPacketSizesPreserveByteWeights(t *testing.T) {
	q := New[int](100, 2000000)
	for i := 0; i < 2000; i++ {
		if err := q.Push(1, protocol.Normal, 50, 50); err != nil {
			t.Fatal(err)
		}
		if err := q.Push(2, protocol.Normal, 500, -500); err != nil {
			t.Fatal(err)
		}
	}
	var a, b int
	for i := 0; i < 1100; i++ {
		v, ok := q.Pop()
		if !ok {
			t.Fatal("early exhaustion")
		}
		if v > 0 {
			a += v
		} else {
			b -= v
		}
	}
	if delta := a - b; delta < -600 || delta > 600 {
		t.Fatalf("equal weights unfair by bytes: %d / %d", a, b)
	}
}

func TestIdleFlowCannotRetainDeficit(t *testing.T) {
	q := New[int](10, 1000)
	_ = q.Push(1, protocol.Interactive, 1, 1)
	_, _ = q.Pop()
	_ = q.Push(2, protocol.Bulk, 10, 2)
	_ = q.Push(1, protocol.Interactive, 40, 1)
	got, _ := q.Pop()
	if got != 2 {
		t.Fatal("idle returning flow jumped the persistent cursor")
	}
	got, _ = q.Pop()
	if got != 1 {
		t.Fatal("returning flow failed to receive service")
	}
}

func TestClassShareIndependentOfFlowCounts(t *testing.T) {
	for _, flowCounts := range [][3]int{{1, 1, 1}, {12, 3, 1}, {1, 1, 12}} {
		q := New[int](100, 10000000)
		id := 0
		classes := map[int]protocol.Class{}
		for class, count := range flowCounts {
			for j := 0; j < count; j++ {
				id++
				classes[id] = protocol.Class(class)
				for n := 0; n < 4000; n++ {
					if err := q.Push(uint64(id), protocol.Class(class), 100, id); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
		var counts [3]int
		perFlow := map[int]int{}
		for n := 0; n < 7000; n++ {
			flow, ok := q.Pop()
			if !ok {
				t.Fatal("early exhaustion")
			}
			counts[classes[flow]]++
			perFlow[flow]++
		}
		if counts != [3]int{4000, 2000, 1000} {
			t.Fatalf("flow counts %v boosted category share: %v", flowCounts, counts)
		}
		for class := range counts {
			low, high := 7000, 0
			for flow, flowClass := range classes {
				if flowClass == protocol.Class(class) {
					low = min(low, perFlow[flow])
					high = max(high, perFlow[flow])
				}
			}
			if high-low > 1 {
				t.Fatalf("category %d unfair within flows: %v", class, perFlow)
			}
		}
	}
}

func TestSingleCategoryWorkConservingAndFairByBytes(t *testing.T) {
	for _, class := range []protocol.Class{protocol.Interactive, protocol.Normal, protocol.Bulk} {
		q := New[int](100, 10000000)
		for flow := 0; flow < 12; flow++ {
			cost := 50
			if flow%2 == 1 {
				cost = 500
			}
			for n := 0; n < 1000; n++ {
				if err := q.Push(uint64(flow), class, cost, flow); err != nil {
					t.Fatal(err)
				}
			}
		}
		var bytes [12]int
		for n := 0; n < 2200; n++ {
			flow, ok := q.Pop()
			if !ok {
				t.Fatal("active single category failed to dispatch")
			}
			if flow%2 == 0 {
				bytes[flow] += 50
			} else {
				bytes[flow] += 500
			}
		}
		low, high := bytes[0], bytes[0]
		for _, n := range bytes {
			low, high = min(low, n), max(high, n)
		}
		if low == 0 || high-low > 600 {
			t.Fatalf("single category %d not byte-fair: %v", class, bytes)
		}
	}
}

func TestReclassificationDoesNotTransferCredit(t *testing.T) {
	q := New[int](1, 1000)
	for n := 0; n < 200; n++ {
		_ = q.Push(1, protocol.Interactive, 1, 1)
		_ = q.Push(2, protocol.Bulk, 1, 2)
	}
	if got, _ := q.Pop(); got != 1 {
		t.Fatal("initial interactive flow not selected")
	}
	if err := q.ReclassifyFlow(1, protocol.Bulk); err != nil {
		t.Fatal(err)
	}
	if q.categories[protocol.Interactive] != nil || q.flows[1].deficit != 0 {
		t.Fatal("class/flow retained old interactive credit")
	}
	counts := [3]int{}
	for n := 0; n < 100; n++ {
		flow, ok := q.Pop()
		if !ok {
			t.Fatal("reclassification exhausted queue")
		}
		counts[flow]++
	}
	if counts[1] != 50 || counts[2] != 50 {
		t.Fatalf("downgrade bypassed flow fairness: %v", counts)
	}
	if err := q.ReclassifyFlow(1, protocol.Interactive); err != nil {
		t.Fatal(err)
	}
	counts = [3]int{}
	for n := 0; n < 50; n++ {
		flow, _ := q.Pop()
		counts[flow]++
	}
	if counts[1] != 40 || counts[2] != 10 {
		t.Fatalf("promoted category failed 4:1 share: %v", counts)
	}
	if err := q.ReclassifyFlow(12345, protocol.Normal); err != nil {
		t.Fatal("unknown flow should be a no-op")
	}
	if err := q.ReclassifyFlow(1, protocol.Class(255)); !errors.Is(err, ErrClass) {
		t.Fatal("invalid reclassification accepted")
	}
}

func TestMixedClassFIFOAndBudgetMigration(t *testing.T) {
	q := NewWithLimits[string](1, Limits{MaxBytes: 30, MaxClassBytes: 10})
	_ = q.Push(1, protocol.Bulk, 4, "first")
	_ = q.Push(1, protocol.Interactive, 4, "second")
	_ = q.Push(2, protocol.Interactive, 4, "other")
	if err := q.ReclassifyFlow(1, protocol.Interactive); !errors.Is(err, ErrFull) {
		t.Fatal("migration ignored per-class byte cap")
	}
	if q.classBytes != [3]int{8, 0, 4} || q.flows[1].category.class != protocol.Bulk || q.flows[1].items[0].class != protocol.Bulk || q.Bytes() != 12 {
		t.Fatal("failed migration changed metadata/budget")
	}
	// The already eligible Interactive peer may dispatch before the Bulk head.
	if got, ok := q.Pop(); !ok || got != "other" {
		t.Fatalf("interactive peer: %q %v", got, ok)
	}
	if got, ok := q.Pop(); !ok || got != "first" || q.flows[1].category.class != protocol.Interactive || q.flows[1].deficit != 0 {
		t.Fatalf("head class migration/FIFO: %q %v", got, ok)
	}
	if q.classBytes != [3]int{4, 0, 0} {
		t.Fatalf("class byte refund: %v", q.classBytes)
	}
	if err := q.ReclassifyFlow(1, protocol.Normal); err != nil {
		t.Fatal(err)
	}
	if q.classBytes != [3]int{0, 4, 0} || q.classItems != [3]int{0, 1, 0} {
		t.Fatal("successful migration accounting")
	}
	seenSecond := false
	for q.Len() > 0 {
		value, _ := q.Pop()
		seenSecond = seenSecond || value == "second"
	}
	if !seenSecond {
		t.Fatal("migration lost pending item")
	}
}

func TestDrainedFlowsReleaseHistoricalBackingArrays(t *testing.T) {
	q := New[int](1, 1000)
	for flow := uint64(1); flow <= 20; flow++ {
		for n := 0; n < 500; n++ {
			if err := q.Push(flow, protocol.Normal, 1, int(flow)); err != nil {
				t.Fatal(err)
			}
		}
		// Keep the flow active with one item, while draining its old allocation.
		dispatches := 0
		for len(q.flows[flow].items) > 1 {
			dispatches++
			if dispatches > 500*int(flow) {
				t.Fatalf("hot rejoining flows starved persistent flow %d", flow)
			}
			value, ok := q.Pop()
			if !ok {
				t.Fatal("early exhaustion")
			}
			// Older one-item flows may dispatch; replenish them rather than
			// retaining historical allocation in a growing population.
			if uint64(value) != flow {
				if err := q.Push(uint64(value), protocol.Normal, 1, value); err != nil {
					t.Fatal(err)
				}
			}
		}
		f := q.flows[flow]
		if f.allocation > 2*len(f.items) {
			t.Fatalf("flow %d retained %d entries for %d pending", flow, f.allocation, len(f.items))
		}
	}
}

func TestHotRejoiningCategoriesCannotStarvePersistentCategory(t *testing.T) {
	q := New[int](1, 10000)
	for n := 0; n < 1000; n++ {
		_ = q.Push(3, protocol.Bulk, 1, 3)
	}
	_ = q.Push(1, protocol.Interactive, 1, 1)
	_ = q.Push(2, protocol.Normal, 1, 2)
	lastBulk, bulkCount := -1, 0
	for n := 0; n < 300; n++ {
		flow, ok := q.Pop()
		if !ok {
			t.Fatal("early exhaustion")
		}
		if flow == 3 {
			if lastBulk >= 0 && n-lastBulk > 3 {
				t.Fatal("hot categories bypassed persistent bulk category")
			}
			lastBulk = n
			bulkCount++
		} else {
			// A single item draining makes the category idle. Its old deficit
			// is intentionally discarded, and rejoining cannot move it ahead
			// of already waiting categories in the logical ring.
			class := protocol.Interactive
			if flow == 2 {
				class = protocol.Normal
			}
			if err := q.Push(uint64(flow), class, 1, flow); err != nil {
				t.Fatal(err)
			}
		}
	}
	if bulkCount != 100 {
		t.Fatalf("persistent category was starved: %d", bulkCount)
	}
}

func TestQueueLimitsAndDropFlow(t *testing.T) {
	tests := []struct {
		name   string
		limits Limits
		seed   []struct {
			id    uint64
			class protocol.Class
			cost  int
		}
		id    uint64
		class protocol.Class
		cost  int
	}{
		{"flows", Limits{MaxBytes: 100, MaxFlows: 1}, []struct {
			id    uint64
			class protocol.Class
			cost  int
		}{{1, protocol.Normal, 1}}, 2, protocol.Bulk, 1},
		{"flow-bytes", Limits{MaxBytes: 100, MaxFlowBytes: 5}, []struct {
			id    uint64
			class protocol.Class
			cost  int
		}{{1, protocol.Normal, 4}}, 1, protocol.Bulk, 2},
		{"first-flow-bytes", Limits{MaxBytes: 100, MaxFlowBytes: 5}, nil, 1, protocol.Bulk, 6},
		{"class-bytes", Limits{MaxBytes: 100, MaxClassBytes: 5}, []struct {
			id    uint64
			class protocol.Class
			cost  int
		}{{1, protocol.Normal, 4}}, 2, protocol.Normal, 2},
		{"items", Limits{MaxBytes: 100, MaxItems: 1}, []struct {
			id    uint64
			class protocol.Class
			cost  int
		}{{1, protocol.Normal, 1}}, 2, protocol.Bulk, 1},
		{"flow-items", Limits{MaxBytes: 100, MaxFlowItems: 1}, []struct {
			id    uint64
			class protocol.Class
			cost  int
		}{{1, protocol.Normal, 1}}, 1, protocol.Bulk, 1},
		{"class-items", Limits{MaxBytes: 100, MaxClassItems: 1}, []struct {
			id    uint64
			class protocol.Class
			cost  int
		}{{1, protocol.Normal, 1}}, 2, protocol.Normal, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := NewWithLimits[int](1, tc.limits)
			for _, seed := range tc.seed {
				if err := q.Push(seed.id, seed.class, seed.cost, 1); err != nil {
					t.Fatal(err)
				}
			}
			beforeBytes, beforeItems, beforeFlows := q.Bytes(), q.Len(), len(q.flows)
			if err := q.Push(tc.id, tc.class, tc.cost, 2); !errors.Is(err, ErrFull) {
				t.Fatalf("cap ignored: %v", err)
			}
			if beforeBytes != q.Bytes() || beforeItems != q.Len() || beforeFlows != len(q.flows) {
				t.Fatal("rejected cap changed queue")
			}
		})
	}
	q := New[int](1, 100)
	_ = q.Push(1, protocol.Interactive, 10, 1)
	_ = q.Push(1, protocol.Bulk, 20, 2)
	_ = q.Push(2, protocol.Normal, 30, 3)
	if n := q.DropFlow(1); n != 2 || q.Bytes() != 30 || q.Len() != 1 || q.classBytes != [3]int{0, 30, 0} || q.classItems != [3]int{0, 1, 0} {
		t.Fatalf("drop accounting: n=%d bytes=%d items=%d classes=%v", n, q.Bytes(), q.Len(), q.classBytes)
	}
	if q.DropFlow(1) != 0 {
		t.Fatal("duplicate drop was not a no-op")
	}
	if got, ok := q.Pop(); !ok || got != 3 || q.Bytes() != 0 || len(q.ring) != 0 {
		t.Fatal("drop corrupted remaining flow")
	}
	_ = q.Push(1, protocol.Bulk, 1, 4)
	if got, _ := q.Pop(); got != 4 {
		t.Fatal("dropped flow could not be requeued")
	}
}

type pendingValue struct {
	id   uint64
	seq  int
	cost int
}

func TestRandomPushPopDropAndReclassifyPreserveState(t *testing.T) {
	q := NewWithLimits[pendingValue](3, Limits{MaxBytes: 500, MaxFlows: 8, MaxFlowBytes: 200, MaxClassBytes: 300, MaxItems: 100, MaxFlowItems: 40, MaxClassItems: 70})
	rng := rand.New(rand.NewSource(8123))
	model := map[uint64][]entry[pendingValue]{}
	for n := 0; n < 10000; n++ {
		id := uint64(rng.Intn(12))
		class := protocol.Class(rng.Intn(3))
		switch rng.Intn(5) {
		case 0, 1:
			v := pendingValue{id: id, seq: n, cost: 1 + rng.Intn(70)}
			if err := q.Push(id, class, v.cost, v); err == nil {
				model[id] = append(model[id], entry[pendingValue]{value: v, cost: v.cost, class: class})
			} else if !errors.Is(err, ErrFull) {
				t.Fatal(err)
			}
		case 2:
			v, ok := q.Pop()
			if !ok {
				if len(model) != 0 {
					t.Fatal("nonempty model but queue did not dispatch")
				}
			} else {
				want := model[v.id]
				if len(want) == 0 || want[0].value != v {
					t.Fatalf("FIFO loss/duplication at %d: %+v want %v", n, v, want)
				}
				if len(want) == 1 {
					delete(model, v.id)
				} else {
					model[v.id] = want[1:]
				}
			}
		case 3:
			if got := q.DropFlow(id); got != len(model[id]) {
				t.Fatalf("drop count %d want %d", got, len(model[id]))
			}
			delete(model, id)
		case 4:
			if err := q.ReclassifyFlow(id, class); err == nil {
				for i := range model[id] {
					model[id][i].class = class
				}
			} else if !errors.Is(err, ErrFull) {
				t.Fatal(err)
			}
		}
		assertQueueState(t, q, model)
	}
	for id := range model {
		q.DropFlow(id)
	}
	assertQueueState(t, q, map[uint64][]entry[pendingValue]{})
}

func assertQueueState(t *testing.T, q *Queue[pendingValue], model map[uint64][]entry[pendingValue]) {
	t.Helper()
	var bytes, items int
	var classBytes, classItems [3]int
	if len(q.flows) != len(model) || q.cursor < 0 || len(q.ring) > 0 && q.cursor >= len(q.ring) {
		t.Fatal("invalid outer ring or flow count")
	}
	seen := map[uint64]bool{}
	for _, c := range q.ring {
		if len(c.ring) == 0 || q.categories[c.class] != c || c.deficit < 0 || c.deficit > q.maxBytes || c.cursor < 0 || c.cursor >= len(c.ring) {
			t.Fatal("invalid category ring/deficit")
		}
		for _, f := range c.ring {
			if seen[f.id] || f.category != c || q.flows[f.id] != f || f.deficit < 0 || f.deficit > q.maxBytes || len(f.items) == 0 || f.items[0].class != c.class {
				t.Fatal("invalid flow placement/deficit")
			}
			seen[f.id] = true
		}
	}
	for id, want := range model {
		f := q.flows[id]
		if f == nil || !seen[id] || len(f.items) != len(want) {
			t.Fatal("missing flow/items")
		}
		var flowBytes int
		for i, e := range f.items {
			if e != want[i] {
				t.Fatal("pending data/class changed unexpectedly")
			}
			flowBytes += e.cost
			classBytes[e.class] += e.cost
			classItems[e.class]++
		}
		if flowBytes != f.bytes || flowBytes > q.limits.MaxFlowBytes || len(f.items) > q.limits.MaxFlowItems || f.allocation < cap(f.items) || f.allocation > 2*len(f.items) {
			t.Fatal("invalid per-flow budget")
		}
		bytes += flowBytes
		items += len(f.items)
	}
	if bytes != q.Bytes() || items != q.Len() || classBytes != q.classBytes || classItems != q.classItems || bytes > q.maxBytes || items > q.limits.MaxItems || len(model) > q.limits.MaxFlows {
		t.Fatal("global/class accounting mismatch")
	}
	for class := range classBytes {
		if classBytes[class] > q.limits.MaxClassBytes || classItems[class] > q.limits.MaxClassItems {
			t.Fatal("category cap exceeded")
		}
	}
}
