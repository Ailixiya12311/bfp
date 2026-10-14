package scheduler

import (
	"bfp/protocol"
	"errors"
	"reflect"
	"testing"
)

type batchFlowState struct {
	Items          []entry[int]
	Bytes, Deficit int
	Class          protocol.Class
}
type batchCategoryState struct {
	Class           protocol.Class
	Deficit, Cursor int
	Visiting        bool
	IDs             []uint64
}
type batchQueueState struct {
	Bytes, Length, Cursor  int
	Visiting               bool
	ClassBytes, ClassItems [3]int
	Flows                  map[uint64]batchFlowState
	Categories             []batchCategoryState
}

func batchSnapshot(q *Queue[int]) batchQueueState {
	out := batchQueueState{Bytes: q.bytes, Length: q.length, Cursor: q.cursor, Visiting: q.visiting, ClassBytes: q.classBytes, ClassItems: q.classItems, Flows: map[uint64]batchFlowState{}}
	for id, f := range q.flows {
		out.Flows[id] = batchFlowState{Items: append([]entry[int](nil), f.items...), Bytes: f.bytes, Deficit: f.deficit, Class: f.category.class}
	}
	for _, c := range q.ring {
		state := batchCategoryState{Class: c.class, Deficit: c.deficit, Cursor: c.cursor, Visiting: c.visiting}
		for _, f := range c.ring {
			state.IDs = append(state.IDs, f.id)
		}
		out.Categories = append(out.Categories, state)
	}
	return out
}

func TestPushBatchRejectsEveryLimitWithoutChangingPendingState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		limits Limits
		id     uint64
		class  protocol.Class
	}{
		{"total-bytes", Limits{MaxBytes: 15}, 1, protocol.Normal},
		{"flow-bytes", Limits{MaxBytes: 100, MaxFlowBytes: 15}, 1, protocol.Normal},
		{"class-bytes", Limits{MaxBytes: 100, MaxClassBytes: 15}, 3, protocol.Normal},
		{"total-items", Limits{MaxBytes: 100, MaxItems: 3}, 1, protocol.Normal},
		{"flow-items", Limits{MaxBytes: 100, MaxFlowItems: 2}, 1, protocol.Normal},
		{"class-items", Limits{MaxBytes: 100, MaxClassItems: 2}, 3, protocol.Normal},
		{"flow-count", Limits{MaxBytes: 100, MaxFlows: 2}, 3, protocol.Normal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := NewWithLimits[int](1, tc.limits)
			_ = q.Push(1, protocol.Normal, 5, 11)
			_ = q.Push(2, protocol.Bulk, 5, 22)
			before := batchSnapshot(q)
			if err := q.PushBatch(tc.id, tc.class, []Item[int]{{Value: 33, Cost: 6}, {Value: 44, Cost: 6}}); !errors.Is(err, ErrFull) {
				t.Fatalf("limit not rejected: %v", err)
			}
			if after := batchSnapshot(q); !reflect.DeepEqual(before, after) {
				t.Fatalf("atomic rejection changed state:\nbefore=%+v\nafter=%+v", before, after)
			}
			seen := map[int]bool{}
			for q.Len() > 0 {
				v, _ := q.Pop()
				seen[v] = true
			}
			if len(seen) != 2 || !seen[11] || !seen[22] {
				t.Fatal("rejected batch corrupted older values")
			}
		})
	}
}

func TestPushBatchValidatesCostClassAndKeepsMixedFIFO(t *testing.T) {
	q := New[int](1, 100)
	_ = q.Push(1, protocol.Bulk, 5, 1)
	before := batchSnapshot(q)
	for _, tc := range []struct {
		class protocol.Class
		items []Item[int]
		err   error
	}{
		{protocol.Normal, []Item[int]{{2, 1}, {3, 0}}, ErrCost},
		{protocol.Normal, []Item[int]{{2, 1}, {3, -1}}, ErrCost},
		{protocol.Normal, []Item[int]{{2, 1}, {3, int(^uint(0) >> 1)}}, ErrFull},
		{protocol.Class(255), []Item[int]{{2, 1}}, ErrClass},
	} {
		if err := q.PushBatch(1, tc.class, tc.items); !errors.Is(err, tc.err) {
			t.Fatalf("invalid batch: %v", err)
		}
		if !reflect.DeepEqual(before, batchSnapshot(q)) {
			t.Fatal("invalid batch mutated state")
		}
	}
	if err := q.PushBatch(1, protocol.Normal, nil); err != nil || !reflect.DeepEqual(before, batchSnapshot(q)) {
		t.Fatal("empty batch not a no-op")
	}
	if err := q.PushBatch(1, protocol.Interactive, []Item[int]{{2, 6}, {3, 7}}); err != nil {
		t.Fatal(err)
	}
	if q.Bytes() != 18 || q.Len() != 3 {
		t.Fatal("batch accounting")
	}
	for _, want := range []int{1, 2, 3} {
		got, ok := q.Pop()
		if !ok || got != want {
			t.Fatalf("batch FIFO %d want%d", got, want)
		}
	}
	if q.Bytes() != 0 || q.Len() != 0 {
		t.Fatal("batch refund")
	}
}
