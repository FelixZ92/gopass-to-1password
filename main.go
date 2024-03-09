package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	gopassapi "github.com/gopasspw/gopass/pkg/gopass/api"
	flag "github.com/spf13/pflag"
)

var (
	excludes  []string
	includes  []string
	secretKey string
	vault     string
)

func main() {
	flag.StringSliceVar(&excludes, "exclude", []string{}, "exclude secret directories")
	flag.StringSliceVar(&includes, "include", []string{}, "include secret directories, ignore others")
	flag.StringVar(&secretKey, "key", "", "secret key to fetch")
	flag.StringVar(&vault, "vault", "Personal", "vault to use")

	flag.Parse()

	ctx := context.Background()
	gp, err := gopassapi.New(ctx)
	if err != nil {
		slog.Error("failed to create gopass", err)
		os.Exit(1)
	}
	defer gp.Close(ctx)

	s, err := gp.List(ctx)
	if err != nil {
		slog.Error("failed to list secrets", err)
		os.Exit(1)
	}

	view := false
	if len(os.Args) > 1 && os.Args[1] == "view" {
		view = true
	}
	fmt.Println(view)

	if view {
		compareSecrets(ctx, gp, s)
		return
	}

	if err := convertSecrets(ctx, gp, s); err != nil {
		slog.Error("failed to convert secrets", err)
		os.Exit(1)
	}
}
