.DEFAULT_GOAL := help
.PHONY: help check test vet build fmt
help:
	@printf '%s\n' '可用指令：' '  make check  檢查格式與靜態分析' '  make test   執行測試' '  make build  建置 CLI 至 bin/tlscheck' '  make fmt    格式化 Go 程式'
check: vet
	git diff --check
vet:
	go vet ./...
test:
	go test ./...
build:
	go build -o bin/tlscheck ./cmd/tlscheck
fmt:
	gofmt -w cmd internal

.PHONY: release-check snapshot verify-packages
release-check:
	goreleaser check
	python3 -B -m unittest discover -s scripts -v
snapshot: release-check
	goreleaser release --snapshot --clean --skip=publish
	python3 scripts/release.py verify
verify-packages:
	python3 scripts/release.py verify
