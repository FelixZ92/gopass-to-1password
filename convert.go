package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/1Password/connect-sdk-go/onepassword"
	"github.com/gopasspw/gopass/pkg/gopass"
	gopassapi "github.com/gopasspw/gopass/pkg/gopass/api"
)

func convertSecrets(ctx context.Context, gp *gopassapi.Gopass, secrets []string) error {
	tmp, err := os.MkdirTemp("", "onepassword")
	if err != nil {
		slog.Error("failed to create temp dir", "error", err)
		os.Exit(1)
	}

	slog.Info("tmp", "dir", tmp)

	for _, secret := range secrets {
		if !shouldHandleSecret(secret) {
			continue
		}

		if err := convertSecret(ctx, gp, secret, tmp); err != nil {
			slog.Error("failed to convert secret", "secret", secret, "error", err)
			continue
		}
	}
	return nil
}

func convertSecret(ctx context.Context, gp *gopassapi.Gopass, path string, tmp string) error {
	secret, err := gp.Get(ctx, path, "")
	if err != nil {
		return err
	}

	pw := to1Password(secret, path)

	b, err := json.Marshal(pw)
	if err != nil {
		return err
	}

	fp := filepath.Join(tmp, pw.Title+".json")
	file, err := os.Create(fp)
	if err != nil {
		return err
	}

	defer func() {
		if err := file.Close(); err != nil {
			slog.Error("failed to close file", "error", err)
		}

		if err := os.Remove(fp); err != nil {
			slog.Error("failed to remove file", "error", err)
		}
	}()

	_, err = file.Write(b)
	if err != nil {
		return err
	}

	cmd := exec.Command("op", "--vault", vault, "item", "create", "--template", fp)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

func to1Password(s gopass.Secret, path string) *onepassword.Item {
	parts := strings.Split(path, "/")
	tags := parts[:len(parts)-1]
	title := strings.Join(parts, "-")

	category := onepasswordCategory(s)

	fields := []*onepassword.ItemField{
		{
			ID:      "password",
			Type:    onepassword.FieldTypeConcealed,
			Purpose: onepassword.FieldPurposePassword,
			Value:   s.Password(),
			Label:   "password",
		},
	}

	sections := []*onepassword.ItemSection{}

	for _, key := range s.Keys() {
		if key == "password" {
			continue
		}
		v, _ := s.Get(key)
		field := &onepassword.ItemField{
			ID:    key,
			Type:  onepassword.FieldTypeString,
			Label: key,
			Value: v,
		}

		if key == "login" {
			field.Purpose = onepassword.FieldPurposeUsername
			field.ID = "username"
			field.Label = "username"
			if strings.Contains(v, "@") {
				field.Type = onepassword.FieldTypeEmail
			}
		}

		if shouldConceal(key) {
			section := &onepassword.ItemSection{
				ID:    key,
				Label: key,
			}
			field.Type = onepassword.FieldTypeConcealed
			field.Section = section
			sections = append(sections, section)
		}

		if strings.Contains(v, "\n") {
			field.Purpose = onepassword.FieldPurposeNotes
		}

		if key == "url" || key == "website" {
			continue
		}

		fields = append(fields, field)
	}

	var urls []onepassword.ItemURL
	if slices.Contains(s.Keys(), "url") {
		url, _ := s.Get("url")
		urls = append(urls, onepassword.ItemURL{
			Label:   "website",
			URL:     url,
			Primary: true,
		})
	} else if slices.Contains(s.Keys(), "website") {
		url, _ := s.Get("website")
		urls = append(urls, onepassword.ItemURL{
			Label:   "website",
			URL:     url,
			Primary: true,
		})
	}

	item := &onepassword.Item{
		Title:    title,
		Category: category,
		Fields:   fields,
		URLs:     urls,
		Sections: sections,
		Tags:     tags,
	}

	return item
}

func onepasswordCategory(s gopass.Secret) onepassword.ItemCategory {
	keys := s.Keys()
	if slices.Contains(keys, "login") && slices.Contains(keys, "url") {
		return onepassword.Login
	}

	return onepassword.Password
}

func shouldConceal(key string) bool {
	return strings.Contains(key, "auth") ||
		strings.Contains(key, "token") ||
		strings.Contains(key, "secret") ||
		strings.Contains(key, "pin") ||
		strings.Contains(key, "puk") ||
		strings.Contains(key, "totp") ||
		strings.Contains(key, "sig")
}
