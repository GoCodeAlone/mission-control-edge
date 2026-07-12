#!/usr/bin/env bash
set -euo pipefail
export LANG=C
export LC_ALL=C

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
package_root="$repository_root/sdk/typescript"
temporary_directory=$(mktemp -d)
trap 'rm -rf "$temporary_directory"' EXIT

node - "$package_root/package.json" "$package_root/package-lock.json" <<'NODE'
const fs = require("node:fs");
for (const path of process.argv.slice(2)) {
  const document = JSON.parse(fs.readFileSync(path, "utf8"));
  const inspect = (value) => {
    if (typeof value === "string" && /^(?:file|link|workspace):/.test(value)) {
      throw new Error(`${path} contains a local dependency: ${value}`);
    }
    if (Array.isArray(value)) value.forEach(inspect);
    else if (value !== null && typeof value === "object") Object.values(value).forEach(inspect);
  };
  inspect(document);
}
NODE

(cd "$package_root" && npm run build >/dev/null)
pack_result=$(cd "$package_root" && npm pack --ignore-scripts --json --pack-destination "$temporary_directory")
tarball=$(node -e 'const value=JSON.parse(process.argv[1]);if(value.length!==1)process.exit(1);process.stdout.write(value[0].filename)' "$pack_result")
archive="$temporary_directory/$tarball"
contents="$temporary_directory/contents.txt"
tar -tzf "$archive" | LC_ALL=C sort >"$contents"

required=(
  package/package.json
  package/dist/LICENSE
  package/dist/NOTICE
  package/dist/README.md
  package/dist/index.js
  package/dist/index.cjs
  package/dist/index.d.ts
  package/dist/index.d.cts
  package/dist/index.js.map
  package/dist/index.cjs.map
  package/dist/examples/provider.js
  package/dist/examples/provider.js.map
  package/dist/schema/command.v1alpha1.schema.json
  package/dist/schema/event.v1alpha1.schema.json
  package/dist/schema/openrpc.v1alpha1.json
  package/dist/schema/provider-manifest.v1alpha1.schema.json
  package/dist/schema/session.v1alpha1.schema.json
)
for path in "${required[@]}"; do
  if ! grep -Fqx "$path" "$contents"; then
    echo "packed TypeScript SDK is missing $path" >&2
    exit 1
  fi
done

allowed=$(printf '%s\n' "${required[@]}" | LC_ALL=C sort)
if ! diff -u <(printf '%s\n' "$allowed") "$contents"; then
  echo "packed TypeScript SDK contains undeclared files" >&2
  exit 1
fi

if grep -Eq '^package/(src|test|examples|testdata|node_modules)/|(^|/)(tsconfig|vitest\.config|package-lock)' "$contents"; then
  echo "packed TypeScript SDK contains development-only files" >&2
  exit 1
fi

mkdir -p "$temporary_directory/unpacked"
tar -xzf "$archive" -C "$temporary_directory/unpacked"
node - "$temporary_directory/unpacked/package/package.json" <<'NODE'
const fs = require("node:fs");
const packageJSON = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
if (packageJSON.name !== "@gocodealone/mission-control-provider-sdk") throw new Error("package name changed");
if (packageJSON.license !== "Apache-2.0") throw new Error("package license changed");
if (packageJSON.engines?.node !== ">=22") throw new Error("Node 22+ is required");
if (packageJSON.publishConfig?.provenance !== undefined) throw new Error("GitHub Packages publish must not claim npm provenance");
if (packageJSON.main !== "./dist/index.cjs" || packageJSON.module !== "./dist/index.js") {
  throw new Error("dual-package entry points are incomplete");
}
const root = packageJSON.exports?.["."];
if (root?.types !== "./dist/index.d.ts" || root?.import !== "./dist/index.js" || root?.require !== "./dist/index.cjs") {
  throw new Error("package exports are incomplete");
}
if (packageJSON.exports?.["./schema/*"] !== "./dist/schema/*") throw new Error("schema exports are missing");
NODE

consumer="$temporary_directory/consumer"
mkdir -p "$consumer"
(cd "$consumer" && npm install --ignore-scripts --no-audit --no-fund "$archive" >/dev/null)
node - "$consumer/consumer.mts" <<'NODE'
const fs = require("node:fs");
fs.writeFileSync(process.argv[2], `
import {
  PROTOCOL_VERSION,
  protocolError,
  type ProviderInitializeRequest,
} from "@gocodealone/mission-control-provider-sdk";
const request: ProviderInitializeRequest | undefined = undefined;
const version: typeof PROTOCOL_VERSION = "mission-control.provider.v1alpha1";
void request;
void version;
void protocolError("cancelled");
`);
NODE
node - "$consumer/consumer.cts" <<'NODE'
const fs = require("node:fs");
fs.writeFileSync(process.argv[2], `
import { PROTOCOL_VERSION, protocolError } from "@gocodealone/mission-control-provider-sdk";
const version: typeof PROTOCOL_VERSION = "mission-control.provider.v1alpha1";
void version;
void protocolError("cancelled");
`);
NODE
"$package_root/node_modules/.bin/tsc" --noEmit --strict --skipLibCheck --target ES2023 --module NodeNext --moduleResolution NodeNext "$consumer/consumer.mts" "$consumer/consumer.cts"
(
  cd "$consumer"
  node --input-type=module -e 'import("@gocodealone/mission-control-provider-sdk").then((sdk)=>{if(sdk.PROTOCOL_VERSION!=="mission-control.provider.v1alpha1")process.exit(1)})'
  node -e 'const sdk=require("@gocodealone/mission-control-provider-sdk");if(sdk.PROTOCOL_VERSION!=="mission-control.provider.v1alpha1")process.exit(1)'
)
