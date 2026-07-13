# Provider protocol security

Mission providers are isolated, untrusted processes. The public JSON protocol
is not the in-process Workflow plugin ABI, and implementing a capability never
grants access to the hosted control plane or its domain records.

## Authority boundary

A provider may report its roles, capabilities, opaque native identifiers, local
sequence, timestamps, payloads, and namespaced extensions. It may not assign a
tenant, project, work item, gateway, canonical session, correlation ID,
sensitivity ceiling, authorization result, or verification tier. The gateway
rejects such fields and constructs canonical envelopes from an authorized local
mapping. Rejection is recursive across provider payloads and extension values.
Known `artifact.*` events must carry a typed provider-local report whose
provider, role, stream, and native session match the event envelope; canonical
creator, hosted locality, classification, and review state cannot be smuggled
through an opaque payload. Provider event names are also allowlisted; extension
events must be reverse-DNS namespaced, so a provider cannot synthesize an
approval, finalization, or verification outcome merely by choosing its name.

Provider manifests and events cannot establish verification. `unverified` is a
control-plane projection when no applicable authoritative evidence exists.
Native-contract and live tiers require exact artifact/platform/suite/config/data
mode matches and trusted Mission signatures. A live run starts with a separately
Mission-signed authorization and ends with a separately gateway-signed receipt.
Admission exact-matches their tenant, gateway, authorization, correlation,
subject, nonce, budget, credential, usage, audit, and authorized gateway signing
key bindings, then consumes the nonce idempotently for that evidence ID. The
final Mission evidence can be
projected repeatedly without turning replay state into provider authority.
Failed, expired, revoked, superseded, forged, or mismatched evidence remains
auditable but never authorizes work.

## Input and replay controls

Decoders bound document and extension sizes, reject duplicate JSON keys,
validate closed enums, and redact validation errors. Mutating capabilities
declare exactly one delivery class. Commands bind ID, idempotency key,
cancellation reference, deadline, and delivery class. Approval decisions bind
the exact command digest plus current session, work/resource/context/policy
revisions, exact role-bound provider artifacts, gateway, scope, expiry, and a
one-use nonce. Rejected and expired decisions remain valid audit records but
cannot authorize dispatch.

Signed isolation and content-custody evidence is issued by an enrolled gateway
key for a single session/policy/provider/environment/configuration/image. It is
short-lived and replay-protected. A provider signature or self-reported control
is insufficient. Same-OS process separation does not by itself prove sandbox or
ephemeral-content custody.

Configuration, context, and structured message digests are verified against
their whitespace-compacted JSON before dispatch. A syntactically valid digest
that does not name the supplied value is rejected.

Provider stdout is protocol-only. Credentials, prompts, terminal bytes, file
content, native state, and raw local paths must not appear in diagnostics,
events, extensions, or hosted metadata. Secrets are passed by reference and
materialized only within an authorized local boundary.

Provider artifact reports carry local provenance and opaque resource locators,
not human identity or review authority. Gateway/control-plane records assign the
canonical session, creator, review state, and hosted locality. Protocol error
codes and messages are closed and bounded so an untrusted provider cannot turn
prompt, terminal, path, or credential content into logs.
