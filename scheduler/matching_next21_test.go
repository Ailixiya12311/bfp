package scheduler

import (
	"bfp/protocol"
	"testing"
)

func TestMatchingNext21PreservesItemsAndBudget(t *testing.T) {
	q := New[int](10, 1000)
	q.Push(1, protocol.Bulk, 30, 11)
	q.Push(1, protocol.Interactive, 20, 12)
	q.Push(1, protocol.Normal, 40, 13)
	q.Push(2, protocol.Normal, 50, 21)
	if value, ok := q.PopMatching(func(n int) bool { return n == 12 }); !ok || value != 12 || q.Bytes() != 120 || q.Len() != 3 {
		t.Fatal("matching extraction changed retained costs/order")
	}
	if b, n := q.DropMatching(1, func(v int) bool { return v == 11 }); b != 30 || n != 1 || q.Bytes() != 90 || q.Len() != 2 {
		t.Fatal("head category deletion changed budget")
	}
	seen := map[int]bool{}
	for q.Len() > 0 {
		v, ok := q.Pop()
		if !ok || seen[v] {
			t.Fatal("broken category/flow ring")
		}
		seen[v] = true
	}
	if !seen[13] || !seen[21] || q.Bytes() != 0 {
		t.Fatal("retained values/budget missing")
	}
	q.Push(1, protocol.Interactive, 90, 31)
	q.Push(1, protocol.Bulk, 60, 32)
	if b, n := q.DropMatching(1, func(int) bool { return true }); b != 150 || n != 2 || q.Bytes() != 0 || q.Len() != 0 {
		t.Fatal("complete matching drop retained budget")
	}
	if _, ok := q.PopMatching(func(int) bool { return true }); ok {
		t.Fatal("empty ring returned value")
	}
}
