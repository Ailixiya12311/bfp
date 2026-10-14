// Package scheduler provides an owner-confined, bounded hierarchical byte DRR
// queue. Queue is not safe for concurrent use. Each flow is FIFO; its head item's
// class determines the outer category. Categories receive total weights 4:2:1,
// independent of their flow counts, and flows within a category have equal byte
// weights. The caller accounts for encoding, padding, and other wire overhead.
package scheduler

import (
	"errors"

	"bfp/protocol"
)

var (
	ErrFull  = errors.New("scheduler: queue budget exceeded")
	ErrCost  = errors.New("scheduler: cost must be positive")
	ErrClass = errors.New("scheduler: invalid class")
)

// Limits are pending queue limits, not transport in-flight limits. Zero optional
// fields inherit MaxBytes, the intrinsic cardinality bound from positive costs.
// MaxClassBytes/Items apply to the declared class of each queued item, including
// items behind a head in another class. A rejection leaves all state unchanged.
type Limits struct {
	MaxBytes      int
	MaxFlows      int
	MaxFlowBytes  int
	MaxClassBytes int
	MaxItems      int
	MaxFlowItems  int
	MaxClassItems int
}

type entry[T any] struct {
	value T
	cost  int
	class protocol.Class
}

// Item is one pending value and its complete wire cost in an atomic flow batch.
type Item[T any] struct {
	Value T
	Cost  int
}

type flow[T any] struct {
	id         uint64
	items      []entry[T]
	allocation int
	bytes      int
	deficit    int
	category   *category[T]
}

type category[T any] struct {
	class    protocol.Class
	deficit  int
	ring     []*flow[T]
	cursor   int
	visiting bool
}

type Queue[T any] struct {
	quantum    int
	maxBytes   int
	limits     Limits
	bytes      int
	length     int
	classBytes [3]int
	classItems [3]int
	flows      map[uint64]*flow[T]
	categories [3]*category[T]
	ring       []*category[T]
	cursor     int
	visiting   bool
}

// New preserves the original total-byte-budget API. For tighter flow/category
// or cardinality limits use NewWithLimits. Invalid parameters panic.
func New[T any](quantum int, maxBytes int) *Queue[T] {
	return NewWithLimits[T](quantum, Limits{MaxBytes: maxBytes})
}

func NewWithLimits[T any](quantum int, limits Limits) *Queue[T] {
	if quantum <= 0 || limits.MaxBytes <= 0 {
		panic("scheduler: positive quantum and MaxBytes required")
	}
	for _, v := range []*int{&limits.MaxFlows, &limits.MaxFlowBytes, &limits.MaxClassBytes, &limits.MaxItems, &limits.MaxFlowItems, &limits.MaxClassItems} {
		if *v < 0 {
			panic("scheduler: limits must not be negative")
		}
		if *v == 0 || *v > limits.MaxBytes {
			*v = limits.MaxBytes
		}
	}
	return &Queue[T]{quantum: min(quantum, limits.MaxBytes), maxBytes: limits.MaxBytes, limits: limits, flows: make(map[uint64]*flow[T])}
}

func (q *Queue[T]) Len() int   { return q.length }
func (q *Queue[T]) Bytes() int { return q.bytes }

// PopMatching extracts a bounded control item without submitting earlier
// ineligible business items. The relative order of all retained items stays
// unchanged. This is reserved for a carrier's temporary business pause.
func (q *Queue[T]) PopMatching(eligible func(T) bool) (T, bool) {
	for _, c := range q.ring {
		for _, f := range c.ring {
			for i, e := range f.items {
				if eligible(e.value) {
					value := e.value
					q.removeItem(f, i)
					return value, true
				}
			}
		}
	}
	var zero T
	return zero, false
}

// DropMatching removes one flow's obsolete message fragments, charging back
// their exact queue cost. Other messages and control items retain their order.
func (q *Queue[T]) DropMatching(id uint64, drop func(T) bool) (bytes, count int) {
	f := q.flows[id]
	if f == nil {
		return 0, 0
	}
	for i := len(f.items) - 1; i >= 0; i-- {
		if drop(f.items[i].value) {
			bytes += f.items[i].cost
			count++
			q.removeItem(f, i)
		}
	}
	return bytes, count
}

func (q *Queue[T]) removeItem(f *flow[T], index int) {
	e := f.items[index]
	q.bytes -= e.cost
	q.length--
	q.classBytes[e.class] -= e.cost
	q.classItems[e.class]--
	f.bytes -= e.cost
	copy(f.items[index:], f.items[index+1:])
	f.items[len(f.items)-1] = entry[T]{}
	f.items = f.items[:len(f.items)-1]
	if len(f.items) == 0 {
		q.detach(f)
		delete(q.flows, f.id)
		f.items = nil
		f.allocation = 0
	} else if f.category.class != f.items[0].class {
		q.detach(f)
		q.attach(f, f.items[0].class)
	}
}

// Push charges cost once to pending queue budgets. It preserves per-item class
// and per-flow FIFO semantics: a later differently classified item cannot pass
// earlier items. ReclassifyFlow explicitly changes an entire pending flow.
func (q *Queue[T]) Push(id uint64, class protocol.Class, cost int, value T) error {
	if cost <= 0 {
		return ErrCost
	}
	if !class.Valid() {
		return ErrClass
	}
	f := q.flows[id]
	if cost > q.maxBytes-q.bytes || cost > q.limits.MaxClassBytes-q.classBytes[class] || q.length == q.limits.MaxItems || q.classItems[class] == q.limits.MaxClassItems {
		return ErrFull
	}
	if f == nil {
		if len(q.flows) == q.limits.MaxFlows || cost > q.limits.MaxFlowBytes {
			return ErrFull
		}
		f = &flow[T]{id: id}
		q.flows[id] = f
		q.attach(f, class)
	} else if cost > q.limits.MaxFlowBytes-f.bytes || len(f.items) == q.limits.MaxFlowItems {
		return ErrFull
	}
	q.appendItem(f, class, cost, value)
	return nil
}

// PushBatch atomically admits a whole flow batch under every configured limit.
// Failure preserves earlier queued values, ring cursors, and all accounting.
// Queue ownership excludes concurrent mutations between validation and commit.
func (q *Queue[T]) PushBatch(id uint64, class protocol.Class, items []Item[T]) error {
	if !class.Valid() {
		return ErrClass
	}
	if len(items) == 0 {
		return nil
	}
	cost := 0
	for _, item := range items {
		if item.Cost <= 0 {
			return ErrCost
		}
		if item.Cost > q.maxBytes-cost {
			return ErrFull
		}
		cost += item.Cost
	}
	f := q.flows[id]
	flowBytes, flowItems := 0, 0
	if f == nil {
		if len(q.flows) == q.limits.MaxFlows {
			return ErrFull
		}
	} else {
		flowBytes, flowItems = f.bytes, len(f.items)
	}
	if cost > q.maxBytes-q.bytes || cost > q.limits.MaxClassBytes-q.classBytes[class] || cost > q.limits.MaxFlowBytes-flowBytes || len(items) > q.limits.MaxItems-q.length || len(items) > q.limits.MaxClassItems-q.classItems[class] || len(items) > q.limits.MaxFlowItems-flowItems {
		return ErrFull
	}
	if f == nil {
		f = &flow[T]{id: id}
		q.flows[id] = f
		q.attach(f, class)
	}
	for _, item := range items {
		q.appendItem(f, class, item.Cost, item.Value)
	}
	return nil
}

func (q *Queue[T]) appendItem(f *flow[T], class protocol.Class, cost int, value T) {
	previousCapacity := cap(f.items)
	f.items = append(f.items, entry[T]{value: value, cost: cost, class: class})
	if cap(f.items) != previousCapacity {
		f.allocation = cap(f.items)
	}
	f.bytes += cost
	q.bytes += cost
	q.length++
	q.classBytes[class] += cost
	q.classItems[class]++
}

func (q *Queue[T]) attach(f *flow[T], class protocol.Class) {
	c := q.categories[class]
	if c == nil {
		c = &category[T]{class: class}
		q.categories[class] = c
		if len(q.ring) == 0 {
			q.ring = append(q.ring, c)
		} else {
			// Insert at the logical tail, immediately before the current
			// cursor. Physical-tail insertion can starve the ring prefix when
			// short categories repeatedly drain and rejoin during a visit.
			q.ring = insertBefore(q.ring, q.cursor, c)
			q.cursor++
		}
	}
	f.category = c
	f.deficit = 0
	if len(c.ring) == 0 {
		c.ring = append(c.ring, f)
	} else {
		c.ring = insertBefore(c.ring, c.cursor, f)
		c.cursor++
	}
}

func insertBefore[E any](ring []*E, index int, value *E) []*E {
	ring = append(ring, nil)
	copy(ring[index+1:], ring[index:])
	ring[index] = value
	return ring
}

func (q *Queue[T]) detach(f *flow[T]) {
	c := f.category
	index := 0
	for c.ring[index] != f {
		index++
	}
	copy(c.ring[index:], c.ring[index+1:])
	c.ring[len(c.ring)-1] = nil
	c.ring = c.ring[:len(c.ring)-1]
	if index < c.cursor {
		c.cursor--
	} else if index == c.cursor {
		c.visiting = false
	}
	if c.cursor >= len(c.ring) {
		c.cursor = 0
	}
	f.category = nil
	f.deficit = 0
	if len(c.ring) != 0 {
		return
	}
	index = 0
	for q.ring[index] != c {
		index++
	}
	copy(q.ring[index:], q.ring[index+1:])
	q.ring[len(q.ring)-1] = nil
	q.ring = q.ring[:len(q.ring)-1]
	if index < q.cursor {
		q.cursor--
	} else if index == q.cursor {
		q.visiting = false
	}
	if q.cursor >= len(q.ring) {
		q.cursor = 0
	}
	q.categories[c.class] = nil
	c.deficit = 0
}

// DropFlow removes all pending items for id, returning the item count. In-flight
// records and reliable-send buffers remain the caller's responsibility.
func (q *Queue[T]) DropFlow(id uint64) int {
	f := q.flows[id]
	if f == nil {
		return 0
	}
	n := len(f.items)
	for i, e := range f.items {
		q.classBytes[e.class] -= e.cost
		q.classItems[e.class]--
		f.items[i] = entry[T]{}
	}
	q.bytes -= f.bytes
	q.length -= n
	f.items = nil
	f.allocation = 0
	f.bytes = 0
	q.detach(f)
	delete(q.flows, id)
	return n
}

// ReclassifyFlow atomically moves all pending items into a class, retaining FIFO
// but discarding the flow's old deficit. Existing category credit belongs to the
// category, never transfers with the flow, and resets when a category empties.
// The class/category limits are checked before any mutation. Unknown id is a no-op.
func (q *Queue[T]) ReclassifyFlow(id uint64, class protocol.Class) error {
	if !class.Valid() {
		return ErrClass
	}
	f := q.flows[id]
	if f == nil {
		return nil
	}
	var movedBytes, movedItems int
	for _, e := range f.items {
		if e.class != class {
			movedBytes += e.cost
			movedItems++
		}
	}
	if movedBytes == 0 {
		return nil
	}
	if movedBytes > q.limits.MaxClassBytes-q.classBytes[class] || movedItems > q.limits.MaxClassItems-q.classItems[class] {
		return ErrFull
	}
	for i, e := range f.items {
		if e.class != class {
			q.classBytes[e.class] -= e.cost
			q.classItems[e.class]--
			f.items[i].class = class
		}
	}
	q.classBytes[class] += movedBytes
	q.classItems[class] += movedItems
	q.detach(f)
	q.attach(f, class)
	return nil
}

func (q *Queue[T]) quantumFor(class protocol.Class) int {
	weight := 1
	if class == protocol.Interactive {
		weight = 4
	} else if class == protocol.Normal {
		weight = 2
	}
	if q.quantum > q.maxBytes/weight {
		return q.maxBytes
	}
	return q.quantum * weight
}

func addDeficit(deficit, quantum, limit int) int {
	if quantum > limit-deficit {
		return limit
	}
	return deficit + quantum
}

func addRounds(deficit, quantum, rounds, limit int) int {
	if rounds > (limit-deficit)/quantum {
		return limit
	}
	return deficit + rounds*quantum
}

func (c *category[T]) advance() {
	c.cursor = (c.cursor + 1) % len(c.ring)
	c.visiting = false
}

// nextFlow prepares one inner-DRR candidate, retaining its cursor/deficit while
// the outer category waits for enough credit. A huge head with a tiny quantum is
// skipped by arithmetic complete rounds, not one iteration per byte.
func (c *category[T]) nextFlow(quantum, limit int) *flow[T] {
	missed := 0
	for {
		f := c.ring[c.cursor]
		if !c.visiting {
			f.deficit = addDeficit(f.deficit, quantum, limit)
			c.visiting = true
		}
		if f.items[0].cost <= f.deficit {
			return f
		}
		c.advance()
		missed++
		if missed == len(c.ring) {
			rounds := limit
			for _, other := range c.ring {
				shortfall := other.items[0].cost - other.deficit
				need := (shortfall-1)/quantum + 1
				rounds = min(rounds, need-1)
			}
			if rounds > 0 {
				for _, other := range c.ring {
					other.deficit = addRounds(other.deficit, quantum, rounds, limit)
				}
			}
			missed = 0
		}
	}
}

func (q *Queue[T]) advance() {
	q.cursor = (q.cursor + 1) % len(q.ring)
	q.visiting = false
}

func (q *Queue[T]) skipEmptyRounds() {
	rounds := q.maxBytes
	for _, c := range q.ring {
		// Every category has prepared its inner candidate in the failed round.
		shortfall := c.ring[c.cursor].items[0].cost - c.deficit
		quantum := q.quantumFor(c.class)
		need := (shortfall-1)/quantum + 1
		rounds = min(rounds, need-1)
	}
	if rounds > 0 {
		for _, c := range q.ring {
			c.deficit = addRounds(c.deficit, q.quantumFor(c.class), rounds, q.maxBytes)
		}
	}
}

// Pop releases pending cost and returns the next item. Both category and flow
// deficits pay the full cost. This is work-conserving among active categories;
// fixed category ratios concern continuously backlogged queues over time, not
// end-to-end latency or bytes already committed to the underlying TCP socket.
func (q *Queue[T]) Pop() (T, bool) {
	var zero T
	if q.length == 0 {
		return zero, false
	}
	missed := 0
	for {
		c := q.ring[q.cursor]
		if !q.visiting {
			c.deficit = addDeficit(c.deficit, q.quantumFor(c.class), q.maxBytes)
			q.visiting = true
		}
		f := c.nextFlow(q.quantum, q.maxBytes)
		head := f.items[0]
		if head.cost > c.deficit {
			q.advance()
			missed++
			if missed == len(q.ring) {
				q.skipEmptyRounds()
				missed = 0
			}
			continue
		}
		c.deficit -= head.cost
		f.deficit -= head.cost
		f.items[0] = entry[T]{}
		f.items = f.items[1:]
		// A subslice keeps its entire original backing array alive. Compact at
		// geometric thresholds so many mostly drained flows cannot each retain
		// their historical maximum allocation. Copies are amortized by drains.
		if len(f.items) > 0 && len(f.items) <= f.allocation/2 {
			remaining := make([]entry[T], len(f.items))
			copy(remaining, f.items)
			f.items = remaining
			f.allocation = len(remaining)
		}
		f.bytes -= head.cost
		q.bytes -= head.cost
		q.length--
		q.classBytes[head.class] -= head.cost
		q.classItems[head.class]--
		if len(f.items) == 0 {
			q.detach(f)
			delete(q.flows, f.id)
		} else if f.items[0].class != c.class {
			q.detach(f)
			q.attach(f, f.items[0].class)
		} else if f.items[0].cost > f.deficit {
			c.advance()
		}
		return head.value, true
	}
}
