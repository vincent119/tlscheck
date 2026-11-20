package app

import (
	"context"
	"sync"

	"github.com/vincent119/tlscheck/internal/check"
	"github.com/vincent119/tlscheck/internal/input"
	"github.com/vincent119/tlscheck/internal/model"
)

func expandTargetLists(ctx context.Context, o *RunOptions) model.IssueCode {
	if len(o.TargetFiles) > input.MaxTargetLists {
		return input.BatchLimitExceeded
	}
	expanded := []model.InputSpec{}
	used := 0
	p := input.NewParser()
	add := func(spec model.InputSpec) bool {
		if len(expanded) >= input.MaxBatchTargets {
			return false
		}
		spec.Index = len(expanded)
		expanded = append(expanded, spec)
		return true
	}
	for _, spec := range o.Inputs {
		if spec.Kind != model.TargetListInput {
			if !add(spec) {
				return input.BatchLimitExceeded
			}
			continue
		}
		list := p.ReadTargetList(ctx, spec.Value, input.MaxTargetListBytes-used)
		used += list.Bytes
		if list.Issue == input.BatchLimitExceeded {
			return list.Issue
		}
		if list.Issue != "" {
			if !add(model.InputSpec{Kind: model.RemoteInput, ListSource: &model.TargetListSource{Path: spec.Value}, Problem: list.Issue}) {
				return input.BatchLimitExceeded
			}
			continue
		}
		for _, entry := range list.Entries {
			if !add(model.InputSpec{Kind: model.RemoteInput, Value: entry.Value, ListSource: &model.TargetListSource{Path: spec.Value, Line: entry.Line}}) {
				return input.BatchLimitExceeded
			}
		}
	}
	o.Inputs = expanded
	return ""
}

// runRemoteChecks讓每個worker獨佔結果位置；預設循序維持原呼叫邊界，不共用writer。
func runRemoteChecks(ctx context.Context, targets []model.Target, concurrency int, run func(context.Context, model.Target) check.RemoteResult) []check.RemoteResult {
	results := make([]check.RemoteResult, len(targets))
	for i, target := range targets {
		results[i] = check.RemoteResult{Target: target, Stage: "input", Issues: []check.Outcome{{Status: check.Failed, Class: check.ExecutionFailure, Code: "remote.not_scheduled"}}}
	}
	if len(targets) == 0 {
		return results
	}
	if concurrency <= 1 {
		for i, target := range targets {
			if ctx.Err() != nil {
				break
			}
			results[i] = run(ctx, target)
		}
		return results
	}
	jobs := make(chan int)
	var workers sync.WaitGroup
	for range min(concurrency, len(targets)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case i, ok := <-jobs:
					if !ok || ctx.Err() != nil {
						return
					}
					results[i] = run(ctx, targets[i])
				}
			}
		}()
	}
dispatch:
	for i := range targets {
		select {
		case <-ctx.Done():
			break dispatch
		case jobs <- i:
		}
	}
	close(jobs)
	workers.Wait()
	return results
}
