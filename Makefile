.DEFAULT_GOAL := help

.PHONY: help check

help:
	@printf '%s\n' '可用指令：' '  make check  檢查 Git 差異的空白格式' '目前尚無 Go module，建置與測試指令待實作後加入。'

check:
	git diff --check
