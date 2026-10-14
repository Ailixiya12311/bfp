package tunnel

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

func TestRetrySessionFakeIPLeaseFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"direct", C.ErrSessionFakeIP},
		{"wrapped", fmt.Errorf("dial destination: %w", C.ErrSessionFakeIP)},
		{"joined", errors.Join(errors.New("destination unavailable"), C.ErrSessionFakeIP)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			attempts, reports := 0, 0
			_, err := retry(ctx, func(context.Context) (int, error) {
				attempts++
				return 0, tc.err
			}, func(err error) {
				reports++
				if err != tc.err {
					t.Errorf("reported error changed: got %v, want %v", err, tc.err)
				}
			})
			if attempts != 1 || reports != 1 {
				t.Fatalf("retired lease retried: attempts=%d reports=%d", attempts, reports)
			}
			if err != tc.err || !errors.Is(err, C.ErrSessionFakeIP) {
				t.Fatalf("retired lease error changed: got %v, want %v", err, tc.err)
			}
		})
	}

	t.Run("temporary_error_still_retries", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		temporary := errors.New("temporary dial failure")
		attempts, reports := 0, 0
		result, err := retry(ctx, func(context.Context) (int, error) {
			attempts++
			if attempts == 1 {
				return 0, temporary
			}
			return 7, nil
		}, func(err error) {
			reports++
			if err != temporary {
				t.Errorf("unexpected reported error: %v", err)
			}
		})
		if err != nil || result != 7 || attempts != 2 || reports != 1 {
			t.Fatalf("temporary retry changed: result=%d err=%v attempts=%d reports=%d", result, err, attempts, reports)
		}
	})
}
