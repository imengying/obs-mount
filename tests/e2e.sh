#!/usr/bin/env bash
# End-to-end test: mount obs-mount on a mock OBS endpoint and exercise the
# file operations that matter for the backup use case.
#
# Requires: /dev/fuse, python3, a release build, and (for a clean unmount)
# fusermount. Skips itself when /dev/fuse is unavailable, so it is safe to
# run anywhere.
#
#   cargo build --release && ./tests/e2e.sh
#
# Everything it creates lives under a temp dir and is removed on exit; the
# mountpoint is never an existing directory with data in it.

set -uo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BIN=${OBS_MOUNT_BIN:-$REPO/target/release/obs-mount}
PORT=${OBS_MOCK_PORT:-8899}
WORK=$(mktemp -d)
MNT=$WORK/mnt
CONF=$WORK/obs-mount.yaml
ACCESS=$WORK/access.log

server_pid=""
mount_pid=""
failures=0

cleanup() {
  if mountpoint -q "$MNT" 2>/dev/null; then
    fusermount3 -u "$MNT" 2>/dev/null || fusermount -u "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null
  fi
  [ -n "$mount_pid" ] && kill "$mount_pid" 2>/dev/null
  [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

if [ ! -e /dev/fuse ]; then
  echo "SKIP: /dev/fuse not available"
  exit 0
fi
if [ ! -x "$BIN" ]; then
  echo "SKIP: $BIN not built (run: cargo build --release)"
  exit 0
fi

pass() { echo "  ok   $1"; }
fail() { echo "  FAIL $1"; echo "       got: $2"; echo "       want: $3"; failures=$((failures + 1)); }
eq() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1" "$2" "$3"; fi; }

echo "== starting mock OBS on 127.0.0.1:$PORT =="
OBS_MOCK_ACCESS_LOG=$ACCESS python3 "$REPO/tests/mock_obs.py" "$PORT" >"$WORK/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 50); do
  curl -sf "http://127.0.0.1:$PORT/__stats" >/dev/null 2>&1 && break
  sleep 0.1
done

mkdir -p "$MNT"
cat >"$CONF" <<EOF
mountpoint: $MNT
bucket: test-bucket
endpoint: http://127.0.0.1:$PORT
ak: TESTAK
sk: TESTSK
EOF
chmod 600 "$CONF"

echo "== mounting =="
"$BIN" --config "$CONF" >"$WORK/mount.log" 2>&1 &
mount_pid=$!
for _ in $(seq 1 50); do
  mountpoint -q "$MNT" && break
  sleep 0.1
done
if ! mountpoint -q "$MNT"; then
  echo "FAIL: mount did not come up"
  tail -20 "$WORK/mount.log"
  exit 1
fi

cd "$MNT" || exit 1

echo "== basics =="
echo hello >small.txt
eq "small file round-trip" "$(cat small.txt)" "hello"
eq "small file size" "$(stat -c %s small.txt)" "6"

echo "== overwrite the same file repeatedly (regression) =="
ok=1
for i in 1 2 3 4 5; do echo "v$i" >over.txt || ok=0; done
eq "five overwrites succeed" "$ok" "1"
eq "last content wins" "$(cat over.txt)" "v5"

echo "== append =="
printf 'a\n' >app.txt
printf 'b\n' >>app.txt
eq "append" "$(tr '\n' ',' <app.txt)" "a,b,"

echo "== directories =="
mkdir -p d1/d2/d3
echo nested >d1/d2/d3/n.txt
eq "nested write/read" "$(cat d1/d2/d3/n.txt)" "nested"
eq "readdir count" "$(find d1 -type f | wc -l)" "1"

echo "== rename keeps the new name visible immediately (regression) =="
echo Z >rf.txt
mv rf.txt rf2.txt
eq "file rename + immediate read" "$(cat rf2.txt 2>&1)" "Z"
mkdir -p rd/sub
echo Q >rd/sub/q.txt
mv rd rn
eq "dir rename + immediate read" "$(cat rn/sub/q.txt 2>&1)" "Q"

echo "== truncate =="
printf '0123456789' >tr.txt
truncate -s 4 tr.txt
eq "truncate" "$(cat tr.txt)" "0123"

echo "== range read =="
printf 'ABCDEFGHIJ' >rg.txt
eq "read from offset 3" "$(dd if=rg.txt bs=1 skip=3 count=4 2>/dev/null)" "DEFG"

echo "== multipart upload (regression: used to fail on the XML declaration) =="
head -c 20971520 /dev/urandom >big.bin
eq "20 MiB md5" "$(md5sum big.bin | cut -d' ' -f1)" "$(md5sum <big.bin | cut -d' ' -f1)"

echo "== exact threshold boundary =="
head -c 8388608 /dev/urandom >exact.bin
eq "8 MiB md5" "$(md5sum exact.bin | cut -d' ' -f1)" "$(md5sum <exact.bin | cut -d' ' -f1)"

echo "== delete =="
rm rf2.txt
eq "unlink" "$([ -e rf2.txt ] && echo present || echo gone)" "gone"
mkdir empty_dir
rmdir empty_dir
eq "rmdir empty" "$([ -e empty_dir ] && echo present || echo gone)" "gone"
mkdir nonempty
echo x >nonempty/f
rmdir nonempty 2>/dev/null
eq "rmdir non-empty fails" "$?" "1"

echo "== special characters in keys =="
echo S >'a b.txt'
eq "space in name" "$(cat 'a b.txt')" "S"
echo C >'中文.txt'
eq "non-ascii name" "$(cat '中文.txt')" "C"

echo "== statfs reports usage instead of zeros =="
# Regression: fuser's default replies 0 for every field, so df showed
# Size 0 / Avail 0 and anything prechecking free space treated the mount
# as full. A quota-less bucket must report a large synthetic ceiling, never 0.
total=$(df -B1 --output=size /mnt/obs | tail -1 | tr -d ' ')
avail=$(df -B1 --output=avail /mnt/obs | tail -1 | tr -d ' ')
if [ "${total:-0}" -gt 0 ] && [ "${avail:-0}" -gt 0 ]; then
  pass "df reports non-zero size (${total}B total, ${avail}B avail)"
else
  fail "df reports usable capacity" "total=$total avail=$avail" "both > 0"
fi
used=$(df -B1 --output=used /mnt/obs | tail -1 | tr -d ' ')
if [ "${used:-0}" -gt 0 ]; then
  pass "df reports non-zero used bytes"
else
  fail "df reports used bytes" "$used" "> 0"
fi
# The kernel may substitute its own FUSE default for f_namemax, so only
# assert that statvfs() itself works and reports the block size we set.
bsize=$(python3 -c "import os;print(os.statvfs('/mnt/obs').f_frsize)")
eq "statvfs block size" "$bsize" "4096"

echo "== every request must have carried a valid signature =="
stats=$(curl -sf "http://127.0.0.1:$PORT/__stats")
sigfail=$(printf '%s' "$stats" | sed -n 's/.*"signature_failures": \([0-9]*\).*/\1/p')
eq "signature failures" "${sigfail:-unknown}" "0"

cd "$WORK" || exit 1
echo
if [ "$failures" -eq 0 ]; then
  echo "ALL PASSED"
else
  echo "$failures CHECK(S) FAILED"
  echo "--- mount log ---"; tail -30 "$WORK/mount.log"
  [ -f "$ACCESS" ] && { echo "--- requests ---"; tail -40 "$ACCESS"; }
fi
exit $((failures > 0))
