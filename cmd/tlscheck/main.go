// tlscheck 入口只管理取消與統一退出碼。
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/vincent119/tlscheck/internal/app"
)

// 開發預設值不冒充已發佈版本，S08 可透過 ldflags 注入。
var version = "development"
var commit = "unknown"

func main() { os.Exit(run()) }
func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	a := app.New()
	a.Version = version
	a.Commit = commit
	return a.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
}
