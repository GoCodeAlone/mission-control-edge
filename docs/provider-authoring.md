# Provider authoring

A Mission provider is an external process that implements one or more
provider-neutral capabilities. It is not an in-process Workflow plugin, and it
does not need Ratchet, Herdr, or any other particular harness or runtime. The
gateway starts or connects to the process and speaks the Mission provider
protocol over a bounded transport.

## Declare the contract first

Every provider ships a manifest with:

- one or more concern roles: `execution-environment`, `session-runtime`,
  `agent-harness`, or `orchestration`;
- the exact capabilities it implements;
- supported operating-system and architecture pairs;
- interaction modes and local permissions;
- a repository-local provider configuration schema; and
- only reverse-DNS namespaced extension data.

`provider.initialize` and `provider.capabilities` are mandatory and are handled
by both SDK servers. Every other advertised capability must have a matching
handler, and a handler must not exist for an unadvertised capability. For a
known capability, copy its catalog descriptor instead of recreating its role,
mutation flag, or delivery class.

Mutating capabilities use one delivery class:

| Delivery class | Provider obligation |
| --- | --- |
| `provider_idempotent` | Persist mutation identity before the side effect and return the same outcome for the same command. |
| `state_reconciled` | Inspect native state and converge it to the requested state; do not assume a retry means no earlier effect occurred. |
| `at_most_once` | Never blindly replay an ambiguous command. Return `outcome_unknown` when the effect cannot be proved. |

The SDKs keep bounded, process-local command records. A provider that promises
recovery across process restarts must persist its own mutation identity and
native reconciliation data.

## Minimal Go provider

This provider advertises session inventory and returns an empty inventory. It
uses only public APIs from the `protocol` and `provider` packages.

```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"

	"github.com/GoCodeAlone/mission-control-edge/protocol"
	"github.com/GoCodeAlone/mission-control-edge/provider"
)

func main() {
	manifest := protocol.ProviderManifest{
		ProtocolVersion: protocol.Version,
		ID:              "example-runtime",
		Roles:           []protocol.ProviderRole{protocol.RoleSessionRuntime},
		Name:            "Example Runtime Provider",
		Version:         "0.1.0",
		Executable:      "example-runtime-provider",
		Platforms: []protocol.Platform{{
			OS: runtime.GOOS, Architecture: runtime.GOARCH,
		}},
		Capabilities: []protocol.CapabilityDescriptor{
			capability("provider.initialize"),
			capability("provider.capabilities"),
			capability("runtime.list_sessions"),
		},
		InteractionModes:    []string{"json-rpc"},
		Permissions:         []string{},
		ConfigurationSchema: "schema.json",
		Extensions:          map[string]json.RawMessage{},
	}

	handlers := provider.HandlerSet{Runtime: provider.RuntimeHandlers{
		Sessions: provider.RuntimeSessionHandlers{
			List: func(context.Context, protocol.RuntimeListSessionsRequest) (protocol.RuntimeListSessionsResult, error) {
				return protocol.RuntimeListSessionsResult{Sessions: []protocol.RuntimeSession{}}, nil
			},
		},
	}}
	server, err := provider.NewServer(
		provider.ServerConfig{Manifest: manifest, AuthenticationModes: []string{"none"}},
		handlers,
	)
	if err == nil {
		err = server.Serve(context.Background(), os.Stdin, os.Stdout)
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "provider_failed")
		os.Exit(1)
	}
}

func capability(name protocol.CapabilityName) protocol.CapabilityDescriptor {
	value, ok := protocol.Capability(name)
	if !ok {
		panic("unknown static capability")
	}
	return value
}
```

Use `provider.WithLimits` to replace `provider.DefaultLimits` only with an
explicit, validated bound. Mutation handlers receive `provider.MutationMeta`;
its raw command and digest are integrity data and must never be logged.
Subscription handlers return `provider.EventSubscription`,
`provider.TerminalSubscription`, or `provider.TopologySubscription`. Producers
that continue after setup use `provider.SubscriptionContext(ctx)` for their
lifetime.

## Minimal TypeScript provider

Node.js 22 or newer is required. The package exports the server, catalog, types,
strict framing helpers, and protocol constants from
`@gocodealone/mission-control-provider-sdk`.

```ts
import { arch, platform } from "node:process";

import {
  CAPABILITY_CATALOG,
  PROTOCOL_VERSION,
  ProviderServer,
  type CapabilityDescriptor,
  type ProviderManifest,
} from "@gocodealone/mission-control-provider-sdk";

const capability = (name: CapabilityDescriptor["name"]): CapabilityDescriptor => {
  const value = CAPABILITY_CATALOG.find((entry) => entry.name === name);
  if (value === undefined) throw new Error("unknown static capability");
  return { ...value };
};

const manifest: ProviderManifest = {
  protocol_version: PROTOCOL_VERSION,
  id: "example-runtime",
  roles: ["session-runtime"],
  name: "Example Runtime Provider",
  version: "0.1.0",
  executable: "example-runtime-provider",
  platforms: [{
    os: platform === "win32" ? "windows" : platform,
    architecture: arch === "x64" ? "amd64" : arch,
  }],
  capabilities: [
    capability("provider.initialize"),
    capability("provider.capabilities"),
    capability("runtime.list_sessions"),
  ],
  interaction_modes: ["json-rpc"],
  permissions: [],
  configuration_schema: "schema.json",
  extensions: {},
};

const server = new ProviderServer({
  manifest,
  authenticationModes: ["none"],
  replaySupported: false,
  handlers: {
    "runtime.list_sessions": () => ({ sessions: [] }),
  },
});

try {
  await server.serve();
} catch {
  process.stderr.write("provider_failed\n");
  process.exitCode = 1;
}
```

Mutation handlers receive an `AbortSignal` and the validated command in their
handler context. Stop promptly on cancellation. Use `providerSubscription` for
event, terminal, and topology subscriptions; its replay is acknowledged before
notifications are emitted, and an optional `AsyncIterable` can supply live
notifications.

The `none` authentication mode in these examples is suitable only for a local
example or a separately protected process boundary. Deployment policy chooses
the permitted authentication mode.

## Stdio and lifecycle rules

The default transport is strict newline-delimited JSON-RPC on stdin/stdout:

- stdout is protocol-only; never use it for logs, progress, prompts, or terminal
  bytes outside protocol frames;
- each frame is one non-empty JSON object followed by one LF; CRLF, blank lines,
  primitives, arrays, duplicate keys, and an unterminated final frame fail;
- the hard envelope limit is 4 MiB, and initialization may negotiate a smaller
  envelope or terminal-chunk limit;
- initialization completes before any other capability is accepted;
- request IDs, command IDs, native IDs, offsets, and sequence numbers remain
  opaque or monotonic as defined by the protocol; and
- browser or gateway disconnection does not imply that native work stopped.

Stderr may contain bounded, content-free operational markers. It must not
contain request or response bodies, prompts, terminal output, credentials,
paths, native state, or provider error detail. The SDK deliberately returns
closed protocol errors for the same reason.

## Safety checklist

Before publishing a provider:

- keep it independently installable and run it as a separate process;
- request only the local permissions it uses;
- treat native identifiers as opaque values, never paths or authority;
- pass credentials by reference and resolve them inside the authorized local
  boundary;
- bound queues, in-flight work, retained idempotency records, subscriptions,
  terminal windows, and shutdown time;
- honor cancellation and command deadlines without claiming that an ambiguous
  side effect was rolled back;
- validate compact-JSON digests before using configuration, context, or agent
  messages;
- never put tenant, project, work-item, canonical-session, review, approval, or
  verification authority into provider payloads or extensions; and
- run the external-process conformance suite described in
  [conformance.md](conformance.md).

The complete runnable examples are
[`cmd/mc-provider-example`](../cmd/mc-provider-example) and
[`sdk/typescript/examples/provider.ts`](../sdk/typescript/examples/provider.ts).
Protocol compatibility and authority rules are documented in
[`protocol/compatibility.md`](../protocol/compatibility.md) and
[`protocol/security.md`](../protocol/security.md).
