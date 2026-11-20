package app

import (
	"context"
	"strconv"
	"strings"

	"github.com/vincent119/tlscheck/internal/input"
	"github.com/vincent119/tlscheck/internal/model"
)

func bindCompareCertificates(ctx context.Context, o *RunOptions) error {
	if len(o.CompareCertBindings) == 0 {
		return nil
	}
	o.CompareCertPaths = map[int]string{}
	parser := input.NewParser()
	for _, raw := range o.CompareCertBindings {
		indexText, path, ok := strings.Cut(raw, "=")
		if !ok || indexText == "" || path == "" || path == "-" || strings.ContainsRune(path, 0) {
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
		if _, exists := o.CompareCertPaths[index]; exists {
			return errArguments
		}
		spec := o.Inputs[index]
		if spec.Problem != "" || spec.Kind == model.LocalInput || spec.Kind == model.TargetListInput {
			return errArguments
		}
		if spec.Kind == model.AutoInput && len(parser.LocalPaths(ctx, []model.InputSpec{spec})) > 0 {
			return errArguments
		}
		parsed := parser.ParseSpec(ctx, model.InputSpec{Kind: model.RemoteInput, Value: spec.Value, Index: index})
		if parsed.Target == nil || len(parsed.Issues) > 0 {
			return errArguments
		}
		o.CompareCertPaths[index] = path
	}
	return nil
}

func compareTargetsStillRemote(bindings map[int]string, results []model.InputResult) bool {
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
