# Repository Agent Guide

Mission Control Edge is the public gateway, provider protocol, SDK, conformance,
and reference-provider repository for Mission Control.

## Architectural boundaries

- Keep the design provider-neutral. Agent harness, session runtime, execution
  environment, and orchestration providers are independent capability sets.
- The private control plane is a GoCodeAlone Workflow application. Workflow
  drives product automation; this edge repository does not duplicate the
  initiative/project domain model.
- Mission providers are isolated processes using the public Mission protocol,
  not in-process Workflow plugins.
- Treat provider output and extension data as untrusted. Native identifiers are
  opaque and provider-specific fields stay namespaced.
- Do not embed or redistribute Herdr, Ratchet, Codex, Claude Code, credentials,
  installers, source, or native state. Use separately installed versions and
  documented public interfaces.
- Preserve Apache-2.0 license and notice obligations for distributions.

## Working conventions

- Use Go 1.26.4 and standard-library APIs unless a dependency is justified.
- Use test-driven development for behavior changes. Run focused tests first,
  then the full race, vet, lint, vulnerability, and license gates.
- Use `GOWORK=off` when a parent workspace has a `go.work` file.
- Format Go with `gofmt`; avoid global mutable state except for build-time
  version variables.
- Never log or commit prompts, terminal output, credentials, tokens, customer
  data, or provider-native state.
- Keep release workflows tag-only and permissions scoped to the publishing job.
- Do not apply repository governance until every configured required check
  exists and has succeeded.
