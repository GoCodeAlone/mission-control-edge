#!/usr/bin/env bash
set -euo pipefail

repository="GoCodeAlone/mission-control-edge"
module="github.com/GoCodeAlone/mission-control-edge"
package_name="@gocodealone/mission-control-provider-sdk"
registry="https://npm.pkg.github.com"
go_ref=""
npm_spec=""
expected_npm_version="0.1.0"
verify_attestations=false

usage() {
  cat <<'EOF'
Usage: scripts/clean-consumer-proof.sh [options]

  --go-ref REF                  Public Go tag or remotely reachable commit
  --npm-spec SPEC               Local SDK directory or published package spec
  --expected-npm-version VER    Expected package version (default: 0.1.0)
  --verify-attestations         Verify release provenance and SPDX attestations
  --help                        Show this help

Candidate example:
  scripts/clean-consumer-proof.sh --go-ref "$(git rev-parse HEAD)" \
    --npm-spec ./sdk/typescript

Released example:
  scripts/clean-consumer-proof.sh --go-ref v0.1.0 \
    --npm-spec @gocodealone/mission-control-provider-sdk@0.1.0 \
    --verify-attestations
EOF
}

fail() {
  printf 'clean_consumer_proof_failed: %s\n' "$*" >&2
  exit 1
}

while (($# > 0)); do
  case "$1" in
    --go-ref)
      (($# >= 2)) || fail "--go-ref requires a value"
      go_ref=$2
      shift 2
      ;;
    --npm-spec)
      (($# >= 2)) || fail "--npm-spec requires a value"
      npm_spec=$2
      shift 2
      ;;
    --expected-npm-version)
      (($# >= 2)) || fail "--expected-npm-version requires a value"
      expected_npm_version=$2
      shift 2
      ;;
    --verify-attestations)
      verify_attestations=true
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      fail "unknown option: $1"
      ;;
  esac
done

for command in git go node npm tar; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is required"
done

repo_root=$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)
if [[ -z "$go_ref" ]]; then
  go_ref=$(git -C "$repo_root" rev-parse HEAD)
fi
if [[ -z "$npm_spec" ]]; then
  npm_spec="$repo_root/sdk/typescript"
fi

umask 077
temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/mission-control-clean-consumer.XXXXXX")
cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ -d "$temporary_root/gomodcache" ]] && \
    ! GOMODCACHE="$temporary_root/gomodcache" GOWORK=off go clean -modcache >/dev/null 2>&1; then
    chmod -R u+w "$temporary_root/gomodcache" 2>/dev/null || true
    if ! rm -rf "$temporary_root/gomodcache"; then
      status=1
    fi
  fi
  if ! rm -rf "$temporary_root"; then
    printf 'clean_consumer_proof_failed: could not remove temporary consumer\n' >&2
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

case "$temporary_root" in
  "$repo_root"|"$repo_root"/*)
    fail "temporary consumer must be outside the repository"
    ;;
esac

export GOWORK=off
export GOPATH="$temporary_root/gopath"
export GOMODCACHE="$temporary_root/gomodcache"
export GOCACHE="$temporary_root/gocache"
export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"
export NPM_CONFIG_CACHE="$temporary_root/npm-cache"
export NPM_CONFIG_USERCONFIG="$temporary_root/npmrc"
mkdir -p "$GOPATH" "$GOMODCACHE" "$GOCACHE" "$temporary_root/bin"
: >"$NPM_CONFIG_USERCONFIG"

go_consumer="$temporary_root/go-consumer"
mkdir -p "$go_consumer"
(
  cd "$go_consumer"
  go mod init example.com/mission-control-clean-consumer >/dev/null
  go get "$module@$go_ref"
)

cat >"$go_consumer/main.go" <<'EOF'
package main

import (
	"encoding/json"
	"runtime"

	"github.com/GoCodeAlone/mission-control-edge/conformance"
	"github.com/GoCodeAlone/mission-control-edge/protocol"
	"github.com/GoCodeAlone/mission-control-edge/provider"
)

func main() {
	manifest := protocol.ProviderManifest{
		ProtocolVersion: protocol.Version,
		ID: "clean-go-consumer",
		Roles: []protocol.ProviderRole{protocol.RoleAgentHarness},
		Name: "Clean Go Consumer",
		Version: "0.1.0",
		Executable: "clean-go-consumer",
		Platforms: []protocol.Platform{{OS: runtime.GOOS, Architecture: runtime.GOARCH}},
		Capabilities: []protocol.CapabilityDescriptor{
			capability("provider.initialize"),
			capability("provider.capabilities"),
		},
		InteractionModes: []string{"json-rpc"},
		Permissions: []string{},
		ConfigurationSchema: "schema.json",
		Extensions: map[string]json.RawMessage{},
	}
	server, err := provider.NewServer(provider.ServerConfig{
		Manifest: manifest,
		AuthenticationModes: []string{"none"},
	}, provider.HandlerSet{})
	if err != nil {
		panic(err)
	}
	matrix, err := conformance.DefaultMatrix()
	if err != nil {
		panic(err)
	}
	_, _ = server, matrix
}

func capability(name protocol.CapabilityName) protocol.CapabilityDescriptor {
	descriptor, ok := protocol.Capability(name)
	if !ok {
		panic("unknown capability")
	}
	return descriptor
}
EOF

(
  cd "$go_consumer"
  go mod edit -json | node -e '
    let input = "";
    process.stdin.on("data", chunk => input += chunk);
    process.stdin.on("end", () => {
      const mod = JSON.parse(input);
      if (Array.isArray(mod.Replace) && mod.Replace.length > 0) process.exit(1);
    });
  '
  module_dir=$(go list -m -f '{{.Dir}}' "$module")
  case "$module_dir" in
    "$repo_root"|"$repo_root"/*) exit 1 ;;
  esac
  installed_version=$(go list -m -f '{{.Version}}' "$module")
  if [[ "$go_ref" =~ ^[0-9a-f]{40}$ ]]; then
    [[ "$installed_version" == *-"${go_ref:0:12}" ]] || exit 1
  elif [[ "$go_ref" == v* ]]; then
    [[ "$installed_version" == "$go_ref" ]] || exit 1
  fi
  go build -trimpath -o "$temporary_root/bin/clean-go-consumer" .
)

GOBIN="$temporary_root/bin" go install "$module/cmd/mc-conformance@$go_ref"

token="${NODE_AUTH_TOKEN:-${GH_TOKEN:-}}"
if [[ "$npm_spec" == "$package_name"@* ]]; then
  if [[ -z "$token" ]] && command -v gh >/dev/null 2>&1; then
    token=$(gh auth token 2>/dev/null || true)
  fi
  [[ -n "$token" ]] || fail "NODE_AUTH_TOKEN, GH_TOKEN, or authenticated gh is required"
  {
    printf '@gocodealone:registry=%s\n' "$registry"
    printf '//npm.pkg.github.com/:_authToken=%s\n' "$token"
  } >"$NPM_CONFIG_USERCONFIG"
fi
unset token

pack_directory="$temporary_root/package"
mkdir -p "$pack_directory"
if [[ "$npm_spec" == "$package_name"@* ]]; then
  npm pack "$npm_spec" --registry="$registry" --pack-destination "$pack_directory" --silent >/dev/null
else
  npm pack "$npm_spec" --pack-destination "$pack_directory" --silent >/dev/null
fi
tarballs=("$pack_directory"/*.tgz)
[[ ${#tarballs[@]} -eq 1 && -f "${tarballs[0]}" ]] || fail "npm pack did not produce exactly one tarball"
tarball=${tarballs[0]}

tar -tf "$tarball" >"$temporary_root/packed-files.txt"
if grep -Eq '^package/(node_modules|vendor)/' "$temporary_root/packed-files.txt"; then
  fail "npm tarball contains a bundled dependency tree"
fi
tar -xOf "$tarball" package/package.json >"$temporary_root/packed-package.json"
node - "$temporary_root/packed-package.json" "$package_name" "$expected_npm_version" <<'NODE'
const fs = require("node:fs");
const manifest = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
if (manifest.name !== process.argv[3] || manifest.version !== process.argv[4]) process.exit(1);
if (manifest.workspaces !== undefined) process.exit(1);
for (const key of ["bundleDependencies", "bundledDependencies"]) {
  if (manifest[key] !== undefined && (!Array.isArray(manifest[key]) || manifest[key].length > 0)) process.exit(1);
}
for (const section of ["dependencies", "optionalDependencies", "peerDependencies", "devDependencies"]) {
  for (const value of Object.values(manifest[section] ?? {})) {
    if (typeof value !== "string") process.exit(1);
    if (/^(file|link|workspace):/i.test(value) || /^(\.\.?\/|\/)/.test(value)) process.exit(1);
  }
}
NODE

digest=$(node - "$tarball" <<'NODE'
const crypto = require("node:crypto");
const fs = require("node:fs");
const value = crypto.createHash("sha256").update(fs.readFileSync(process.argv[2])).digest("hex");
process.stdout.write(value);
NODE
)

if [[ "$verify_attestations" == true ]]; then
  command -v gh >/dev/null 2>&1 || fail "gh is required for attestation verification"
  attestation_args=(
    --repo "$repository"
    --signer-workflow "$repository/.github/workflows/release.yml"
    --format json
  )
  if [[ "$go_ref" == v* ]]; then
    attestation_args+=(--source-ref "refs/tags/$go_ref")
  fi
  gh attestation verify "$tarball" "${attestation_args[@]}" >"$temporary_root/provenance.json"
  gh attestation verify "$tarball" "${attestation_args[@]}" \
    --predicate-type https://spdx.dev/Document/v2.3 >"$temporary_root/sbom.json"
  node - "$temporary_root/provenance.json" "$temporary_root/sbom.json" "$digest" <<'NODE'
const fs = require("node:fs");
const provenance = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const sbom = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
const digest = process.argv[4];
const hasSubject = entries => entries.some(entry =>
  entry.verificationResult?.statement?.subject?.some(subject => subject.digest?.sha256 === digest));
if (!hasSubject(provenance) || !hasSubject(sbom)) process.exit(1);
if (!sbom.some(entry => entry.verificationResult?.statement?.predicate?.spdxVersion === "SPDX-2.3")) process.exit(1);
NODE
fi

typescript_consumer="$temporary_root/typescript-consumer"
mkdir -p "$typescript_consumer"
cat >"$typescript_consumer/package.json" <<'EOF'
{
  "name": "mission-control-clean-typescript-consumer",
  "private": true,
  "type": "module"
}
EOF
(
  cd "$typescript_consumer"
  npm install --ignore-scripts --no-audit --no-fund --save-exact \
    "$tarball" typescript@5.9.3 @types/node@26.1.1 >/dev/null
)

cat >"$typescript_consumer/tsconfig.json" <<'EOF'
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true,
    "skipLibCheck": false,
    "outDir": "dist"
  },
  "include": ["provider.ts"]
}
EOF

cat >"$typescript_consumer/provider.ts" <<'EOF'
import { arch, platform } from "node:process";
import {
  CAPABILITY_CATALOG,
  PROTOCOL_VERSION,
  ProviderServer,
  type CapabilityDescriptor,
  type ProviderManifest,
} from "@gocodealone/mission-control-provider-sdk";

const capability = (name: CapabilityDescriptor["name"]): CapabilityDescriptor => {
  const descriptor = CAPABILITY_CATALOG.find(candidate => candidate.name === name);
  if (descriptor === undefined) throw new Error("unknown capability");
  return { ...descriptor };
};

const manifest: ProviderManifest = {
  protocol_version: PROTOCOL_VERSION,
  id: "clean-typescript-consumer",
  roles: ["agent-harness"],
  name: "Clean TypeScript Consumer",
  version: "0.1.0",
  executable: "clean-typescript-provider",
  platforms: [{
    os: platform === "win32" ? "windows" : platform,
    architecture: arch === "x64" ? "amd64" : arch,
  }],
  capabilities: [capability("provider.initialize"), capability("provider.capabilities")],
  interaction_modes: ["json-rpc"],
  permissions: [],
  configuration_schema: "schema.json",
  extensions: {},
};

const server = new ProviderServer({
  manifest,
  authenticationModes: ["none"],
  replaySupported: false,
});

await server.serve();
EOF

(
  cd "$typescript_consumer"
  ./node_modules/.bin/tsc -p tsconfig.json
  "$temporary_root/bin/mc-conformance" \
    --provider "node dist/provider.js" \
    --json "$temporary_root/typescript-conformance.json"
)
node - "$temporary_root/typescript-conformance.json" <<'NODE'
const fs = require("node:fs");
const report = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
if (report.provider_id !== "clean-typescript-consumer") process.exit(1);
if (report.results.some(result => result.required && result.status === "failed")) process.exit(1);
NODE

printf 'clean_consumer_proof_passed go_ref=%s npm_version=%s sha256=%s\n' \
  "$go_ref" "$expected_npm_version" "$digest"
