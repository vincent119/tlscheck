package app

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vincent119/tlscheck/internal/check"
	"github.com/vincent119/tlscheck/internal/model"
)

func schedulerTargets(n int) []model.Target {
	out := make([]model.Target, n)
	for i := range out {
		out[i] = model.Target{Host: "example.invalid", ASCIIHost: "example.invalid", Port: 443, InputIndex: i}
	}
	return out
}
func waitScheduler[T any](t *testing.T, ctx context.Context, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-ctx.Done():
		t.Fatal("scheduler回歸未結束")
		var zero T
		return zero
	}
}
func TestBatchConcurrencyIsBoundedAndOutputOrdered(t *testing.T) {
	for _, n := range []int{1, 3} {
		t.Run(string(rune('0'+n)), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			started := make(chan int, 6)
			release := make(chan struct{})
			done := make(chan []check.RemoteResult, 1)
			var active, peak atomic.Int32
			go func() {
				done <- runRemoteChecks(ctx, schedulerTargets(6), n, func(ctx context.Context, target model.Target) check.RemoteResult {
					current := active.Add(1)
					for {
						old := peak.Load()
						if current <= old || peak.CompareAndSwap(old, current) {
							break
						}
					}
					started <- target.InputIndex
					select {
					case <-release:
					case <-ctx.Done():
					}
					active.Add(-1)
					return check.RemoteResult{Target: target}
				})
			}()
			for range n {
				waitScheduler(t, ctx, started)
			}
			if peak.Load() != int32(n) {
				t.Fatal("最大並行不符", peak.Load())
			}
			close(release)
			results := waitScheduler(t, ctx, done)
			if peak.Load() > int32(n) || active.Load() != 0 || len(results) != 6 {
				t.Fatal("超出並行或未等待完成")
			}
			for i, r := range results {
				if r.Target.InputIndex != i {
					t.Fatal("結果順序改變")
				}
			}
		})
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	gates := []chan struct{}{make(chan struct{}), make(chan struct{}), make(chan struct{})}
	started := make(chan int, 3)
	completed := make(chan int, 3)
	done := make(chan []check.RemoteResult, 1)
	go func() {
		done <- runRemoteChecks(ctx, schedulerTargets(3), 3, func(ctx context.Context, target model.Target) check.RemoteResult {
			started <- target.InputIndex
			select {
			case <-gates[target.InputIndex]:
			case <-ctx.Done():
			}
			completed <- target.InputIndex
			return check.RemoteResult{Target: target}
		})
	}()
	for range 3 {
		waitScheduler(t, ctx, started)
	}
	for i := 2; i >= 0; i-- {
		close(gates[i])
		if waitScheduler(t, ctx, completed) != i {
			t.Fatal("反向完成前置條件不符")
		}
	}
	results := waitScheduler(t, ctx, done)
	for i, r := range results {
		if r.Target.InputIndex != i {
			t.Fatal("反向完成改變輸出順序")
		}
	}
}
func TestBatchCancellationStopsAndJoinsWorkers(t *testing.T) {
	parent, stop := context.WithTimeout(t.Context(), 15*time.Second)
	defer stop()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	started := make(chan int, 6)
	done := make(chan []check.RemoteResult, 1)
	var exited atomic.Int32
	go func() {
		done <- runRemoteChecks(ctx, schedulerTargets(6), 2, func(ctx context.Context, target model.Target) check.RemoteResult {
			started <- target.InputIndex
			<-ctx.Done()
			exited.Add(1)
			return check.RemoteResult{Target: target, Issues: []check.Outcome{{Code: "input.canceled", Class: check.ExecutionFailure, Status: check.Failed}}}
		})
	}()
	waitScheduler(t, parent, started)
	waitScheduler(t, parent, started)
	cancel()
	results := waitScheduler(t, parent, done)
	if exited.Load() != 2 || len(started) != 0 {
		t.Fatal("取消後仍開始工作或未等待退出")
	}
	count := 0
	for i, r := range results {
		if r.Target.InputIndex != i || r.Failure() != check.ExecutionFailure {
			t.Fatal("取消結果或索引不符")
		}
		if r.Issues[0].Code == "remote.not_scheduled" {
			count++
		}
	}
	if count != 4 {
		t.Fatal("未排程項目未明確回報", count)
	}
}
