package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	gopassapi "github.com/gopasspw/gopass/pkg/gopass/api"
)

func compareSecrets(ctx context.Context, gp *gopassapi.Gopass, secrets []string) error {
	for _, secret := range secrets {
		if !shouldHandleSecret(secret) {
			continue
		}

		if err := compareSecret(ctx, gp, secret); err != nil {
			return err
		}
	}

	return nil
}

func compareSecret(ctx context.Context, gp *gopassapi.Gopass, path string) error {
	parts := strings.Split(path, "/")
	title := strings.Join(parts, "-")

	secret, err := gp.Get(ctx, path, "")
	if err != nil {
		return err
	}

	slog.Info("secret", "path", path)
	fmt.Println("##### gopass secret #####")
	fmt.Println(string(secret.Bytes()))
	fmt.Println()

	fmt.Println("##### 1password #####")
	cmd := exec.Command("op", "--vault", vault, "item", "get", title)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("Press the Enter Key to continue")
	fmt.Scanln()

	return nil
}
