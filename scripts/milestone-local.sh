#!/bin/bash
# Sameroot walking-skeleton milestone, two nodes on one machine (separate homes),
# connected through iroh. Exits non-zero on the first failed check.
set -uo pipefail
# Usage: cargo build -p samerootd -p sameroot && scripts/milestone-local.sh
bin="$(cd "$(dirname "$0")/.." && pwd)/target/debug"
w="$(mktemp -d)"
trap 'rm -rf "$w"' EXIT
mkdir -p "$w/a" "$w/b" "$w/owner"
export SAMEROOT_OWNER_HOME="$w/owner"
A() { SAMEROOT_HOME="$w/a" "$bin/sameroot" "$@"; }
B() { SAMEROOT_HOME="$w/b" "$bin/sameroot" "$@"; }
fail() { echo "FAIL: $*"; kill $pa $pb 2>/dev/null; exit 1; }
start() { SAMEROOT_HOME="$w/$1" "$bin/samerootd" >> "$w/$1.log" 2>&1 & echo $!; }
wait_ready() { for _ in $(seq 1 60); do SAMEROOT_HOME="$w/$1" "$bin/sameroot" status >/dev/null 2>&1 && return 0; sleep 0.5; done; fail "node $1 not ready"; }
state() { SAMEROOT_HOME="$w/$1" "$bin/sameroot" status | awk '/^database/ {for(i=1;i<=NF;i++) if($i=="state") print $(i+1)}'; }

pa=$(start a); pb=$(start b); wait_ready a; wait_ready b
echo "== owner creates a database; node A is delegated"
A owner init | head -1
out=$(A owner create-db milestone) || fail "create-db"; echo "$out"
db=$(echo "$out" | awk '/^database/ {print $2}')
owner=$(echo "$out" | awk '/^owner/ {print $2}')
A put notes/hello "from A" || fail "A put"
echo "== node B joins through an invite"
B join "$(A invite)" || fail "B join"
for _ in $(seq 1 60); do B get notes/hello --subspace "$owner" 2>/dev/null | grep -q "from A" && break; sleep 0.5; done
B get notes/hello --subspace "$owner" | grep -q "from A" || fail "B did not receive A's write"
echo "ok B reads A's delegated write"
echo "== owner delegates node B too"
bdev=$(B status | awk '/^device/ {print $2}')
B cert add "$(A owner delegate "$db" "$bdev" --days 30 --name node-b)" || fail "cert add"
B status | grep -q "(delegated)" || fail "B is not delegated"
echo "== conflict: both write notes/x"
A put notes/x "A wins?" >/dev/null & B put notes/x "B wins?" >/dev/null; wait %1 2>/dev/null
echo "== delete: B deletes notes/hello"
B del notes/hello || fail "B del"
for _ in $(seq 1 60); do
  sa=$(state a); sb=$(state b)
  [ -n "$sa" ] && [ "$sa" = "$sb" ] && A get notes/hello | grep -q deleted && break; sleep 0.5
done
A get notes/hello | grep -q deleted || fail "A did not see B's delete"
xa=$(A get notes/x | cut -f2); xb=$(B get notes/x | cut -f2)
[ "$xa" = "$xb" ] || fail "conflict resolved differently: A=$xa B=$xb"
echo "ok conflict resolved identically on both: $xa"
echo "ok delete replicated"
echo "== both nodes restart"
kill $pa $pb; wait $pa $pb 2>/dev/null
pa=$(start a); pb=$(start b); wait_ready a; wait_ready b
for _ in $(seq 1 60); do sa=$(state a); sb=$(state b); [ -n "$sa" ] && [ "$sa" = "$sb" ] && break; sleep 0.5; done
A status | grep '^database'; B status | grep '^database'
[ "$(state a)" = "$(state b)" ] || fail "state hashes differ after restart"
echo "ok same state after restart: $(state a)"
B put after/restart "B after restart" >/dev/null
for _ in $(seq 1 60); do A get after/restart 2>/dev/null | grep -q "after restart" && break; sleep 0.5; done
A get after/restart | grep -q "after restart" || fail "no sync after restart"
echo "ok live sync after restart (B redialled A from its saved invite)"
kill $pa $pb; wait $pa $pb 2>/dev/null
echo "MILESTONE (local) PASSED"
