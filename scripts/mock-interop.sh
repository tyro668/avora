#!/usr/bin/env bash
# Run lmbp-conformance and the Go-connector end-to-end test against the
# Node, Python, Java and Rust mock gateways (and the Go reference gateway).
#
#   scripts/mock-interop.sh            # node python go
#   scripts/mock-interop.sh java rust  # the dependency-free JDK / Rust ports
#   scripts/mock-interop.sh node       # just one
#   scripts/mock-interop.sh node-sqlite python-sqlite sdk-go sdk-go-sqlite express fastapi spring-boot spring-boot-sqlite   # SDK variants
#   LMBP_RETENTION_SECONDS= scripts/mock-interop.sh go          # gateways keep their default retention; conformance E6 is skipped
#   scripts/mock-interop.sh go-core     # Go reference gateway with -core-only: every Core (and openai) check passes,
#                                       # the undeclared extension profiles are not applicable
set -euo pipefail
cd "$(dirname "$0")/.."
impls=("${@:-node python go}")
read -r -a impls <<<"${impls[*]}"
tmp=$(mktemp -d)
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done; rm -rf "$tmp"; }
trap cleanup EXIT

export LMBP_TENANT_KEY_ACME LMBP_SIGNING_SEED LMBP_RETENTION_SECONDS
# Every gateway runs with a short retention (default 2 s) so conformance E6
# (finished tasks and their idempotency records are purged) runs too. Set it
# empty to keep each gateway's default (7 days); E6 is then reported as skipped.
ret=${LMBP_RETENTION_SECONDS-2}
LMBP_RETENTION_SECONDS=$ret; [ -n "$ret" ] || unset LMBP_RETENTION_SECONDS
retflag() { [ -n "$ret" ] && echo "$1$ret${2:-}"; return 0; }
LMBP_TENANT_KEY_ACME=$(openssl rand -hex 24)   # never printed
LMBP_SIGNING_SEED=${LMBP_SIGNING_SEED:-$(openssl rand -hex 32)}   # the Go gateway refuses an ephemeral key
go build -o "$tmp/lmbp-conformance" ./cmd/lmbp-conformance

start() { # impl port
  local impl=$1 port=$2
  case $impl in
    node|node-sqlite)
      (cd sdk/node && { [ -d node_modules ] || npm ci --no-audit --no-fund >/dev/null; } && npm run -s build)
      (cd mock/node && [ -d node_modules ] || npm ci --no-audit --no-fund >/dev/null)
      db=(); [ "$impl" = node-sqlite ] && db=(--db "$tmp/node.db")
      node mock/node/gateway.mjs --listen "127.0.0.1:$port" --issuer "http://127.0.0.1:$port" --tenant-profiles mock/tenant-profiles.example.json "${db[@]}" $(retflag "--retention-seconds ") >"$tmp/$impl.log" 2>&1 & ;;
    python|python-sqlite)
      [ -x mock/python/.venv/bin/python ] || { python3 -m venv mock/python/.venv && (cd mock/python && .venv/bin/pip install -q -r requirements.txt); }
      db=(); [ "$impl" = python-sqlite ] && db=(--db "$tmp/python.db")
      (cd mock/python && exec .venv/bin/python gateway.py --listen "127.0.0.1:$port" --issuer "http://127.0.0.1:$port" --tenant-profiles ../tenant-profiles.example.json "${db[@]}" $(retflag "--retention-seconds ")) >"$tmp/$impl.log" 2>&1 & ;;
    go|go-core)
      go build -o "$tmp/avora" ./cmd/avora
      core=(); [ "$impl" = go-core ] && core=(-core-only)
      "$tmp/avora" server "${core[@]}" -listen "127.0.0.1:$port" -db "$tmp/$impl.db" -tenants acme:LMBP_TENANT_KEY_ACME \
        -tenant-profiles mock/tenant-profiles.example.json -issuer "http://127.0.0.1:$port" -chat-ui $(retflag "-retention " s) >"$tmp/$impl.log" 2>&1 & ;;
    java)
      mock/java/build.sh >/dev/null
      java -jar mock/java/build/lmbp-mock.jar --listen "127.0.0.1:$port" --issuer "http://127.0.0.1:$port" --tenant-profiles mock/tenant-profiles.example.json $(retflag "--retention-seconds ") >"$tmp/$impl.log" 2>&1 & ;;
    rust)
      (cd mock/rust && cargo build -q --release)
      mock/rust/target/release/lmbp-mock --listen "127.0.0.1:$port" --issuer "http://127.0.0.1:$port" --tenant-profiles mock/tenant-profiles.example.json $(retflag "--retention-seconds ") >"$tmp/$impl.log" 2>&1 & ;;
    spring-boot|spring-boot-sqlite)   # sdk/java: lmbp-spring-boot-starter in examples/spring-boot-demo
      (cd sdk/java && mvn -B -q -DskipTests install) >"$tmp/$impl.build" 2>&1 || { echo "$impl build failed:"; tail -40 "$tmp/$impl.build"; exit 1; }
      store=memory; [ "$impl" = spring-boot-sqlite ] && store="jdbc:sqlite:$tmp/spring.db"
      TENANT_API_KEY=$LMBP_TENANT_KEY_ACME TENANT_PROFILE_FILE=mock/tenant-profiles.example.json PORT=$port LMBP_ISSUER="http://127.0.0.1:$port" LMBP_STORE=$store \
        java -jar examples/spring-boot-demo/target/spring-boot-demo-0.1.0-SNAPSHOT.jar >"$tmp/$impl.log" 2>&1 & ;;
    express)
      (cd sdk/node && { [ -d node_modules ] || npm ci --no-audit --no-fund >/dev/null; } && npm run -s build)
      (cd examples/express && [ -d node_modules ] || npm ci --no-audit --no-fund >/dev/null)
      TENANT_API_KEY=$LMBP_TENANT_KEY_ACME TENANT_PROFILE_FILE=mock/tenant-profiles.example.json PORT=$port LMBP_ISSUER="http://127.0.0.1:$port" \
        node examples/express/server.mjs >"$tmp/$impl.log" 2>&1 & ;;
    fastapi)
      [ -x examples/fastapi/.venv/bin/python ] || { python3 -m venv examples/fastapi/.venv && (cd examples/fastapi && .venv/bin/pip install -q -r requirements.txt); }
      (cd examples/fastapi && TENANT_API_KEY=$LMBP_TENANT_KEY_ACME TENANT_PROFILE_FILE=../../mock/tenant-profiles.example.json PORT=$port LMBP_ISSUER="http://127.0.0.1:$port" \
        exec .venv/bin/uvicorn app:app --host 127.0.0.1 --port "$port" --ws websockets --log-level warning) >"$tmp/$impl.log" 2>&1 & ;;
    sdk-go|sdk-go-sqlite)   # examples/go-nethttp: the sdk/go module imported from another module
      (cd examples/go-nethttp && go build -o "$tmp/go-nethttp" .)
      db=""; [ "$impl" = sdk-go-sqlite ] && db="$tmp/sdkgo.db"
      TENANT_API_KEY=$LMBP_TENANT_KEY_ACME TENANT_PROFILE_FILE=mock/tenant-profiles.example.json PORT=$port LMBP_ISSUER="http://127.0.0.1:$port" LMBP_DB=$db \
        "$tmp/go-nethttp" >"$tmp/$impl.log" 2>&1 & ;;
    *) echo "unknown implementation $impl" >&2; exit 2 ;;
  esac
  pids+=($!)
  for _ in $(seq 150); do curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1 && return; sleep 0.2; done
  echo "$impl did not start:"; cat "$tmp/$impl.log"; exit 1
}

port=18900
fail=0
for impl in "${impls[@]}"; do
  port=$((port + 1))
  start "$impl" "$port"
  echo "== $impl (http://127.0.0.1:$port)"
  rf=(); [ -n "$ret" ] && rf=(-retention "${ret}s")
  if [ "$impl" = go-core ]; then
    # Core-only: 0 failed, every core/openai check ran, only undeclared profiles are not applicable.
    if LMBP_TENANT_KEY=$LMBP_TENANT_KEY_ACME "$tmp/lmbp-conformance" -gateway "http://127.0.0.1:$port" -tenant acme "${rf[@]}" -json >"$tmp/$impl.json" 2>"$tmp/$impl.conf" &&
       summary=$(python3 - "$tmp/$impl.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
res, decl = d["results"], {"core", "openai"}
bad = [r["id"] for r in res if not r["pass"] or (r.get("skip") and r["profile"] in decl) or (not r.get("skip") and r["profile"] not in decl)]
if bad:
    sys.exit("unexpected results: " + " ".join(bad))
ran = sum(1 for r in res if not r.get("skip"))
print(f"{ran} core/openai checks, 0 failed; {len(res) - ran} extension checks not applicable (profiles not declared)")
PY
); then
      echo "   conformance (core-only): $summary"
    else
      echo "   conformance (core-only): FAILED"; cat "$tmp/$impl.conf"; python3 -c 'import json,sys; [print(r["id"], r["profile"], r.get("detail","")) for r in json.load(open(sys.argv[1]))["results"] if not r["pass"]]' "$tmp/$impl.json" 2>/dev/null; tail -30 "$tmp/$impl.log"; fail=1
    fi
    continue   # no Anthropic surface: the official-client e2e needs the full gateway
  fi
  if LMBP_TENANT_KEY=$LMBP_TENANT_KEY_ACME "$tmp/lmbp-conformance" -gateway "http://127.0.0.1:$port" -tenant acme "${rf[@]}" >"$tmp/$impl.conf" 2>&1; then
    echo "   conformance: $(tail -1 "$tmp/$impl.conf")"
  else
    echo "   conformance: FAILED"; grep -v '^PASS' "$tmp/$impl.conf"; echo "   --- $impl gateway log (tail)"; tail -30 "$tmp/$impl.log"; fail=1
  fi
  if LMBP_OFFICIAL_CLIENTS=${LMBP_OFFICIAL_CLIENTS-$PWD/scripts/official-clients.sh} LMBP_EXPECT_EXTERNAL=1 LMBP_EXTERNAL_GATEWAY="http://127.0.0.1:$port" LMBP_TENANT=acme LMBP_TENANT_KEY=$LMBP_TENANT_KEY_ACME \
      scripts/strict-test.py go -count=1 ./mock/external -run TestExternalGateway >"$tmp/$impl.e2e" 2>&1; then
    echo "   connector e2e: ok ($(tail -1 "$tmp/$impl.e2e" | sed 's/^strict-test: ok: //'))"
  else
    echo "   connector e2e: FAILED"; tail -20 "$tmp/$impl.e2e"; fail=1
  fi
done
exit $fail
