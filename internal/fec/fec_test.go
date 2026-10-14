package fec

import (
	"bytes"
	"errors"
	"testing"
)

func testProfile() Profile {
	return Profile{DataShards: 3, ParityShards: 1, ShardSize: 32, MaxBlockSize: 128}
}

func TestEncodeAndRecoverSingleDataShard(t *testing.T) {
	p := testProfile()
	payloads := [][]byte{[]byte("interactive"), []byte("normal payload"), bytes.Repeat([]byte{0x7a}, 29)}
	block, err := Encode(p, 7, payloads)
	if err != nil {
		t.Fatal(err)
	}
	shards := append([][]byte(nil), block.Data...)
	shards[1] = nil
	got, err := block.Recover(1, shards)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payloads[1]) {
		t.Fatalf("recovered=%q want=%q", got, payloads[1])
	}
	if !bytes.Equal(block.Data[1], append(payloads[1], make([]byte, p.ShardSize-len(payloads[1]))...)) {
		t.Fatal("block data mutated")
	}
}

func TestEmptyAndFullSizePayloads(t *testing.T) {
	p := testProfile()
	payloads := [][]byte{nil, bytes.Repeat([]byte{1}, p.ShardSize), []byte("x")}
	block, err := Encode(p, 9, payloads)
	if err != nil {
		t.Fatal(err)
	}
	shards := append([][]byte(nil), block.Data...)
	shards[0] = nil
	got, err := block.Recover(0, shards)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("empty shard length=%d", len(got))
	}
}

func TestProfileAndRecoveryBounds(t *testing.T) {
	for _, p := range []Profile{{}, {DataShards: 33, ParityShards: 1, ShardSize: 1, MaxBlockSize: 33}, {DataShards: 1, ParityShards: 2, ShardSize: 1, MaxBlockSize: 1}, {DataShards: 1, ParityShards: 1, ShardSize: 1, MaxBlockSize: 0}} {
		if err := p.Validate(); !errors.Is(err, ErrProfile) {
			t.Fatalf("profile %+v err=%v", p, err)
		}
	}
	p := testProfile()
	if _, err := Encode(p, 1, [][]byte{{1}}); !errors.Is(err, ErrBlock) {
		t.Fatalf("count error=%v", err)
	}
	block, err := Encode(p, 1, [][]byte{{1}, {2}, {3}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = block.Recover(9, block.Data); !errors.Is(err, ErrBlock) {
		t.Fatalf("index error=%v", err)
	}
	shards := append([][]byte(nil), block.Data...)
	shards[0] = []byte{1}
	if _, err = block.Recover(1, shards); !errors.Is(err, ErrBlock) {
		t.Fatalf("shape error=%v", err)
	}
}
