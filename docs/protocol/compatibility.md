# Provider protocol compatibility

The initial protocol namespace is `mission-control.provider.v1alpha1`. A
gateway and provider negotiate an exact supported namespace during
initialization; neither side may silently reinterpret another namespace.
The generated JSON-RPC description targets OpenRPC 1.4.1.
Initialization succeeds only when the selected protocol, gateway platform,
required capabilities, limits, replay behavior, authentication mode, and
experimental features are compatible with the gateway offer.

Within v1alpha1, consumers must tolerate additive fields and preserve unknown
values inside namespaced `extensions`. Required capabilities are fail-closed:
when a peer does not advertise one, it returns the structured `not_supported`
error with the required and advertised capabilities. Optional namespaced
capabilities may be ignored without changing core behavior.

A manifest declares one or more independent provider roles. A single provider
may combine execution-environment, session-runtime, agent-harness, and
orchestration roles when its advertised capabilities pass the same conformance
rules. Universal `provider.*`, `events.*`, and reconciliation methods are
role-neutral. A known method must use the catalog's exact mutation and delivery
semantics; extension methods use a reverse-DNS namespace and cannot redefine a
reserved method.

Provider-native identifiers are opaque. Consumers may store and return them but
must not split, normalize, URL-decode, path-clean, or derive authority from
them. Provider events contain provider-local scope only; the gateway assigns
tenant, gateway, canonical-session, correlation, sensitivity, and authority
fields. A canonical session ID is required only when the provider event is
session-scoped; provider health and recovery events remain sessionless.
Providers may emit only the core event names enumerated by the protocol;
additional event names require the same reverse-DNS namespace form as extension
capabilities. Approval, review, finalization, and verification outcomes are not
provider-emittable core events.

Security-bearing structures are version-closed. Approval bindings and signed
isolation, custody, authorization, receipt, and verification payloads bind exact
bytes and revisions;
adding a security-relevant field requires a new signing purpose, required
capability, or protocol namespace. Command digests are SHA-256 over the exact
validated JSON bytes persisted and dispatched. The protocol does not claim RFC
8785/JCS canonicalization.

Signed protocol values use a deliberately narrow canonical encoding. The
preimage is the ASCII protocol namespace, one NUL byte, the signing purpose,
one NUL byte, and compact JSON in the declared wire-field order. Signature
algorithm, purpose, issuer, and key ID remain in that JSON while only the
signature value is empty. Set-like slices are sorted before encoding, and
signed strings are restricted to the documented safe ASCII alphabet. These
rules, plus the exact documents, preimages, keys, and signatures in
`protocol/testdata/valid/signing-vectors.json`, are the Go/TypeScript
interoperability contract; ambient object/map iteration is never part of it.
Every SDK must consume those shared vectors rather than reconstructing a
language-specific example. The member order encoded by each exact
`preimage_base64url` value is normative for that signed document type,
including nested signed records.

Embedded configuration, context, and agent-message digests are SHA-256 over
the JSON value after whitespace-only compaction, with member and array order
preserved. Duplicate keys are invalid. This binds the bytes used at the provider
boundary without claiming RFC 8785 canonicalization.

The generated OpenRPC document exhaustively maps every advertised core
capability to its public request and result shape. Generation fails when a
catalog entry has no mapping. Provider configuration schemas are repository-
local relative references; absolute, remote, backslash, and traversal forms
are invalid.

Released v1alpha1 SDKs may receive backward-compatible validation tightening
for inputs that were already invalid. Changing framing, field meaning, delivery
class, signature purpose, or an accepted enum requires a new protocol
namespace. Unknown structured error codes are preserved and handled as failure.

## Release compatibility

Release `v0.1.0` is the first public SDK and conformance release for
`mission-control.provider.v1alpha1`. The Go module, npm package, generated
schemas, command-line tools, and embedded conformance matrix in that release
describe one contract. Mixing those artifacts across versions is unsupported
unless a later release explicitly records the combination as compatible.

The alpha namespace is not a promise of source compatibility across future
protocol namespaces. Within a released namespace, patch releases preserve
valid wire behavior and may reject inputs that were already outside the
published schema. Additive optional fields remain forward-tolerant, while new
required fields, capabilities, signing inputs, delivery semantics, or enum
values require negotiation through a new namespace or capability.

Providers advertise their SDK and native runtime versions separately. A
gateway must select the exact negotiated protocol namespace and treat the
provider's native version as opaque diagnostic data, not as a substitute for
capability negotiation.

## Clean-consumer proof

The repository's `scripts/clean-consumer-proof.sh` resolves the Go module by a
public tag or remotely reachable commit with `GOWORK=off`, rejects module
replacement, and compiles a provider using only the public `protocol`,
`provider`, and `conformance` packages. It separately installs an npm tarball
into a new project, rejects `file:`, `link:`, `workspace:`, absolute, and sibling
dependencies, compiles a TypeScript provider, and runs the released conformance
command against that provider.

For a release, pass `--verify-attestations`. The proof downloads the exact npm
tarball, verifies repository- and tag-bound provenance plus its SPDX 2.3
attestation, and requires the locally computed SHA-256 digest to match the
subject in both signed statements. It never uses a sibling checkout or an npm
workspace alias as release evidence.

GitHub Packages requires an authenticated npm client even when the package is
public. Supply `NODE_AUTH_TOKEN`, `GH_TOKEN`, or an authenticated `gh` CLI; the
proof writes the credential only to its permission-restricted temporary npm
configuration and removes the directory on exit.
