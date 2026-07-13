# Provider conformance

The conformance suite tests a provider through the same external process and
protocol boundary used by a gateway. It never imports a provider implementation
or substitutes a mock for provider behavior. Mocks control the gateway side and
inject deterministic transport or control-plane faults.

## What a case means

One committed, data-driven case format is consumed by the runner for providers
written in Go, TypeScript, or any other language. Each case identifies its
stable scenario, the capability it exercises when applicable, whether failure
is contract-failing, and the normalized expected outcome.

The runner first initializes the provider and records its advertised
capabilities. Baseline protocol cases always apply. Capability-specific cases
are mapped to the manifest: a provider is not penalized for an optional
capability it does not advertise. A skip is recorded separately from a pass and
states why the runner could not collect applicable evidence. An unadvertised
operation must return the structured `not_supported` error rather than a generic
failure.

The initial matrix covers:

- initialization and capability negotiation;
- required and optional capabilities plus structured errors;
- duplicate, out-of-order, conflicting, and replay-gap events;
- disconnect, reconnect, crash, and recovery;
- cancellation and deadlines;
- bounded queues, backpressure, oversized frames, and terminal credit;
- terminal encoding, offsets, truncation, replay, and redaction; and
- `provider_idempotent`, `state_reconciled`, and `at_most_once` mutation
  behavior.

Package unit tests remain useful evidence, but they are not a conformance run.
The process under test must execute its production SDK server and real protocol
handlers.

## Run a provider

From the repository root, build a provider outside the working tree and pass
its command to the runner:

```sh
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

GOWORK=off go build -o "$tmpdir/go-provider" ./cmd/mc-provider-example
GOWORK=off go run ./cmd/mc-conformance --provider "$tmpdir/go-provider"
```

The TypeScript reference provider is exercised by the same runner and case
data:

```sh
(
  cd sdk/typescript
  npm ci
  npm run build
)
GOWORK=off go run ./cmd/mc-conformance \
  --provider "node sdk/typescript/dist/examples/provider.js"
```

`--provider` accepts one quote-aware command string and executes the parsed
executable directly without a shell. It supports single quotes, double quotes,
and backslash escapes. Do not construct the command from untrusted input.

For repository development, run both language paths and the race-enabled suite:

```sh
GOWORK=off go test ./conformance ./mock -race -count=1
(
  cd sdk/typescript
  npm test
)
```

## Results and exit status

The CLI accepts:

- `--provider <command>` (required): external provider executable and arguments;
- `--json <path>`: JSON destination, defaulting to `-` for stdout;
- `--junit <path>`: optional JUnit XML destination; and
- `--timeout <duration>`: per-case timeout, defaulting to `15s`.

For example:

```sh
GOWORK=off go run ./cmd/mc-conformance \
  --provider "$tmpdir/go-provider" \
  --json "$tmpdir/conformance.json" \
  --junit "$tmpdir/conformance.xml" \
  --timeout 5s
```

The JSON report schema is
`mission-control.conformance.report.v1alpha1`. Its top level records
`suite_version`, provider and protocol identity, start/finish timestamps,
`results`, and `capability_cases`. Each result records the stable case ID and
description, optional capability, required flag, `passed`/`failed`/`skipped`
status, duration, optional structured error code, and bounded summary. The JSON
report is the machine-readable source for:

- provider and protocol identity;
- the advertised capability-to-case mapping;
- normalized pass, fail, and skip outcomes; and
- whether each result affects the conformance exit status.

JUnit represents the same normalized cases for CI systems. A skipped case is
distinct from a passing case. Exit status is `0` when no required case fails,
`1` when a required case fails, and `2` for invalid arguments, runner setup, or
report-writing failure. Reports and console output use bounded, content-free
diagnostics; they do not copy protocol frames, terminal bytes, prompts,
credentials, paths, or native state.

For providers advertising the same capability surface, Go and TypeScript runs
are equivalent only when normalization produces the same case IDs,
applicability, outcomes, and protocol error codes. Providers with different
capabilities can have different applicability and skip sets. Language-specific
exception text, stack traces, timing noise, and process IDs are not part of the
contract.

## Conformance is not verification authority

A passing report says that the invoked provider process passed the recorded
cases with its observed manifest on the recorded platform. By itself the report
is not cryptographic proof of executable identity, configuration identity,
sandbox isolation, content custody, production reliability, or fitness for an
unrelated version.

Providers cannot assign themselves a Mission Control verification tier. A
local unsigned conformance report leaves the provider `unverified` for
control-plane authorization. Later release admission may turn an exact,
trusted, repository-bound report into `native_contract_tested` evidence.
`live_verified` additionally requires a Mission-authorized one-use live run, a
matching gateway-signed receipt, and final Mission evidence. The conformance CLI
must never write any of those tiers into provider output.

## Add or change a case

Keep cases deterministic and provider-neutral:

1. Add the case to the shared data set under `conformance/testdata`.
2. Drive the external provider through a real request, notification, process,
   or transport boundary.
3. Inject faults from the mock gateway or control-plane side without
   reimplementing provider logic.
4. Assert a normalized protocol result, including the exact structured error
   code where failure is expected.
5. Run the case against both reference providers and the full race-enabled
   matrix.

Do not weaken a published required case to accommodate one provider. A true
contract change follows the compatibility policy in
[`protocol/compatibility.md`](../protocol/compatibility.md); provider-specific
behavior belongs in a reverse-DNS extension and its own tests.
