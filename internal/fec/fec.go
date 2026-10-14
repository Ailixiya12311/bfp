// Package fec provides a bounded, single-loss XOR repair block for BFP
// datagrams. It is deliberately independent of Session state and wire framing:
// callers must authenticate the block metadata and enforce generation/flow/
// direction scope before accepting a shard.
package fec

import (
	"errors"
	"fmt"
)

var (
	ErrProfile = errors.New("fec: invalid profile")
	ErrBlock   = errors.New("fec: invalid block")
	ErrMissing = errors.New("fec: cannot recover requested shard")
)

// Profile bounds one repair block. XOR repair recovers at most one missing
// data shard; a later profile may add stronger coding without changing the
// ownership and lifetime rules around a Block.
type Profile struct {
	DataShards   int
	ParityShards int
	ShardSize    int
	MaxBlockSize int
}

func (p Profile) Validate() error {
	// This first profile is deliberately one-loss XOR. Stronger codes may be
	// added as a new profile instead of silently pretending that four parity
	// shards are generated here.
	if p.DataShards < 1 || p.DataShards > 32 || p.ParityShards != 1 {
		return fmt.Errorf("%w: shard counts", ErrProfile)
	}
	if p.ShardSize < 1 || p.ShardSize > 16<<10 {
		return fmt.Errorf("%w: shard size", ErrProfile)
	}
	if p.MaxBlockSize <= 0 || p.MaxBlockSize > 1<<20 || p.DataShards*p.ShardSize > p.MaxBlockSize {
		return fmt.Errorf("%w: block size", ErrProfile)
	}
	return nil
}

// Block owns copies of the padded data and parity shards. It does not retain
// Session, carrier, or target references, and it is safe to discard after its
// bounded lifetime expires.
type Block struct {
	ID      uint64
	Profile Profile
	Lengths []uint16
	Data    [][]byte
	Parity  [][]byte
}

// Encode creates one XOR parity shard for a fixed-size data set. All payloads
// are copied and padded to ShardSize. The caller must provide exactly
// DataShards payloads; empty payloads are valid and preserve their length.
func Encode(p Profile, id uint64, payloads [][]byte) (Block, error) {
	if err := p.Validate(); err != nil {
		return Block{}, err
	}
	if len(payloads) != p.DataShards {
		return Block{}, fmt.Errorf("%w: data shard count", ErrBlock)
	}
	b := Block{ID: id, Profile: p, Lengths: make([]uint16, p.DataShards), Data: make([][]byte, p.DataShards), Parity: make([][]byte, 1)}
	parity := make([]byte, p.ShardSize)
	for i, payload := range payloads {
		if len(payload) > p.ShardSize || len(payload) > 1<<16-1 {
			return Block{}, fmt.Errorf("%w: payload %d too large", ErrBlock, i)
		}
		b.Lengths[i] = uint16(len(payload))
		b.Data[i] = make([]byte, p.ShardSize)
		copy(b.Data[i], payload)
		for j := range parity {
			parity[j] ^= b.Data[i][j]
		}
	}
	b.Parity[0] = parity
	return b, nil
}

// Recover reconstructs exactly one absent data shard from the other data
// shards and the first parity shard. The supplied slices may be nil only for
// the missing index. It returns a fresh padded shard trimmed to its original
// length. No mutation of the Block or input slices occurs.
func (b Block) Recover(missing int, shards [][]byte) ([]byte, error) {
	if err := b.Profile.Validate(); err != nil {
		return nil, err
	}
	if b.ID == 0 && len(b.Data) == 0 {
		return nil, fmt.Errorf("%w: empty block", ErrBlock)
	}
	if missing < 0 || missing >= b.Profile.DataShards || len(shards) != b.Profile.DataShards || len(b.Lengths) != b.Profile.DataShards || len(b.Parity) == 0 || len(b.Parity[0]) != b.Profile.ShardSize {
		return nil, fmt.Errorf("%w: shape", ErrBlock)
	}
	if len(b.Data) != b.Profile.DataShards {
		return nil, fmt.Errorf("%w: data shape", ErrBlock)
	}
	for i, shard := range shards {
		if i == missing {
			if shard != nil {
				return nil, fmt.Errorf("%w: missing shard is present", ErrMissing)
			}
			continue
		}
		if len(shard) != b.Profile.ShardSize {
			return nil, fmt.Errorf("%w: shard %d size", ErrBlock, i)
		}
	}
	out := make([]byte, b.Profile.ShardSize)
	copy(out, b.Parity[0])
	for i, shard := range shards {
		if i != missing {
			for j := range out {
				out[j] ^= shard[j]
			}
		}
	}
	length := int(b.Lengths[missing])
	if length > b.Profile.ShardSize {
		return nil, fmt.Errorf("%w: length", ErrBlock)
	}
	return append([]byte(nil), out[:length]...), nil
}
