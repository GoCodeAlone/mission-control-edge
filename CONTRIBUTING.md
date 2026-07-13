# Contributing

Mission Control Edge is an Apache-2.0 public component of a Workflow-based
platform. Changes must preserve the provider-neutral boundary: the hosted
Workflow application owns orchestration and product records, while providers
remain replaceable, isolated processes reached through public contracts.

## Prerequisites

- Go 1.26.4
- golangci-lint 2.12.2
- govulncheck 1.6.0
- go-licenses 2.0.1

Do not commit credentials, npm tokens, provider-native state, transcripts, or
customer data. Do not copy, link, or redistribute third-party harness/runtime
code unless the repository's license and notices explicitly permit it.

## Development workflow

Create a focused branch from `main`. Write a failing test before implementation,
run it to confirm the intended failure, and make the smallest change that passes.
Keep provider-specific data behind namespaced extensions and treat native
identifiers as opaque.

If a parent workspace contains `go.work`, prefix Go commands with `GOWORK=off`.
Before opening a pull request, run:

```sh
test -z "$(gofmt -l .)"
GOWORK=off go test ./... -race -count=1
GOWORK=off go vet ./...
GOWORK=off golangci-lint run --new-from-rev=origin/main
GOWORK=off govulncheck ./...
GOWORK=off go-licenses check --include_tests --disallowed_types=forbidden,restricted,reciprocal,unknown ./...
git diff --check
```

Pull requests require passing protected checks, resolved review conversations,
and an approving review. Explain the trust-boundary and compatibility effects
of protocol, provider, packaging, or permission changes.

By contributing, you agree that your contribution is licensed under the Apache
License 2.0.
