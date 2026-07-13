# Mission Control Edge

Mission Control Edge is the public, customer-operated execution side of the
Mission Control platform. It will contain the provider protocol, provider SDKs,
the edge gateway, and provider-neutral reference implementations.

The hosted Mission Control control plane is an application built with the
[GoCodeAlone Workflow](https://github.com/GoCodeAlone/workflow) framework.
Workflow drives orchestration, schedules, events, approvals, and automation;
the control plane remains the system of record for initiatives, projects,
policy, and outcomes. This repository supplies the language-neutral process
boundary used to reach customer-controlled execution environments. Mission
providers are isolated processes and are not Workflow plugins.

## Status

The v0.1 SDK foundation implements the provider-neutral
`mission-control.provider.v1alpha1` contract, generated JSON Schema and OpenRPC
documents, Go and TypeScript provider SDKs, mock boundaries, and an external-
process conformance suite. Gateway supervision, durable local state, and
runtime/harness providers remain later phases; none are implied by the SDK
release.

The control plane is intentionally built as a
[Workflow](https://github.com/GoCodeAlone/workflow) application and will reuse
Workflow modules and plugins for routing, schedules, approvals, persistence,
observability, and deployment. Provider processes stay behind this repository's
language-neutral protocol boundary instead of becoming Workflow plugins.

## Provider SDKs

Go consumers can depend on the public protocol, provider, and conformance
packages directly:

```sh
GOWORK=off go get github.com/GoCodeAlone/mission-control-edge@v0.1.0
```

The TypeScript SDK is published to GitHub Packages. GitHub's npm registry
requires authentication even for public packages:

```sh
export NODE_AUTH_TOKEN="$(gh auth token)"
npm install @gocodealone/mission-control-provider-sdk@0.1.0 \
  --registry=https://npm.pkg.github.com
```

See [provider authoring](docs/provider-authoring.md), the
[conformance guide](docs/conformance.md), and the
[compatibility policy](docs/protocol/compatibility.md) before advertising a
capability. Released archives include `mc-schema`, `mc-provider-example`, and
`mc-conformance` for Linux and macOS on amd64 and arm64.

## Provider and trust boundary

Mission Control composes independent execution-environment, session-runtime,
agent-harness, and orchestration providers by advertised capability. No
provider, harness, terminal runtime, or provider-native identifier is a core
platform dependency.

Providers execute outside the hosted control plane and will be supervised with
explicit local permissions. Provider output, manifests, capabilities, and
native identifiers must be treated as untrusted until validated. Edge releases
will not bundle Herdr, Ratchet, Codex, Claude Code, or their credentials and
native session state. Integrations invoke separately installed, explicitly
authorized versions through public interfaces.

## Development

Go 1.26.4 is required. When the repository is nested below a workspace that
contains `go.work`, disable the parent workspace so checks use this module:

```sh
GOWORK=off go test ./... -race -count=1
GOWORK=off go vet ./...
GOWORK=off golangci-lint run --new-from-rev=origin/main
npm --prefix sdk/typescript ci
npm --prefix sdk/typescript test
```

After a candidate commit is reachable from GitHub, prove both SDKs from fresh
consumer directories with:

```sh
scripts/clean-consumer-proof.sh --go-ref "$(git rev-parse HEAD)" \
  --npm-spec ./sdk/typescript
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the complete bootstrap checks and
[SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

Mission Control Edge is licensed under the Apache License 2.0. See
[LICENSE](LICENSE) and [NOTICE](NOTICE).
