# gopass-to-1password

Simple program to import secrets from gopass into 1password.

As i grew tired of managing gpg keys, i decided to switch to 1password.
This program is a simple way to import secrets from gopass into 1password.

## Important notes

- To add website labels in 1password, you need to add a `website` or `url` field in the gopass secret.
- The primary username field is derived from the `login` field in the gopass secret.

## Installation

```bash
go get github.com/felixz92/gopass-to-1password
```

## Usage

```bash
Usage of gopass-to-1password:
      --exclude strings   exclude secret directories
      --include strings   include secret directories, ignore others
      --key string        secret key to fetch
      --vault string      vault to use (default "Personal")
```
