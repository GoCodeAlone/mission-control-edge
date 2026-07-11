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

This repository is in its Phase 0 bootstrap. The only implemented package
reports build metadata and the supported protocol range,
`mission-control.provider.v1alpha1`. Protocol schemas, SDKs, conformance tests,
gateway behavior, and reference providers will arrive in subsequent changes.

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
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the complete bootstrap checks and
[SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

Mission Control Edge is licensed under the Apache License 2.0. See
[LICENSE](LICENSE) and [NOTICE](NOTICE).
