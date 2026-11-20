package app

import (
	"context"
	"net/netip"
	"strconv"
	"strings"

	"github.com/vincent119/tlscheck/internal/input"
	"github.com/vincent119/tlscheck/internal/model"
)

func bindConnectIPs(ctx context.Context, o *RunOptions) error {
	if len(o.ConnectIPBindings) == 0 {
		return nil
	}
	o.ConnectIPs = map[int]netip.Addr{}
	p := input.NewParser()
	for _, raw := range o.ConnectIPBindings {
		indexText, value, ok := strings.Cut(raw, "=")
		if !ok || indexText == "" {
			return errArguments
		}
		for _, c := range indexText {
			if c < '0' || c > '9' {
				return errArguments
			}
		}
		index, err := strconv.Atoi(indexText)
		if err != nil || index >= len(o.Inputs) {
			return errArguments
		}
		if _, exists := o.ConnectIPs[index]; exists {
			return errArguments
		}
		spec := o.Inputs[index]
		if spec.Problem != "" || spec.Kind == model.LocalInput || spec.Kind == model.TargetListInput {
			return errArguments
		}
		if spec.Kind == model.AutoInput && len(p.LocalPaths(ctx, []model.InputSpec{spec})) > 0 {
			return errArguments
		}
		parsed := p.ParseSpec(ctx, model.InputSpec{Kind: model.RemoteInput, Value: spec.Value, Index: index})
		if parsed.Target == nil || len(parsed.Issues) > 0 {
			return errArguments
		}
		address, err := netip.ParseAddr(value)
		if err != nil || address.Zone() != "" {
			return errArguments
		}
		o.ConnectIPs[index] = address
	}
	return nil
}

// 再檢查實際分類，避免自動輸入在前處理後被外部程序換成檔案時仍錯綁。
func connectTargetsStillRemote(bindings map[int]netip.Addr, results []model.InputResult) bool {
	for index := range bindings {
		found := false
		for _, r := range results {
			if r.InputIndex == index && r.Target != nil && r.Target.InputIndex == index && len(r.Issues) == 0 {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
