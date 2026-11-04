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

# Is $1 a mountpoint? Reads /proc rather than shelling out to `mountpoint`,
# which some minimal images do not ship -- a missing binary made this report
# "mount failed" when the mount was actually fine.
is_mounted() {
  awk -v p="$1" '{ for (i = 5; i <= NF; i++) if ($i == p) found = 1 } END { exit !found }' \
    /proc/self/mountinfo 2>/dev/null
}

cleanup() {
  if is_mounted "$MNT"; then
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
if [ ! -r /dev/fuse ] || [ ! -w /dev/fuse ]; then
  echo "SKIP: /dev/fuse not accessible to $(id -un)"
  ls -l /dev/fuse
  exit 0
fi
if [ ! -x "$BIN" ]; then
  echo "SKIP: $BIN not built (run: cargo build --release)"
  exit 0
fi

pass() { echo "  ok   $1"; }
fail() { echo "  FAIL $1"; echo "       got: $2"; echo "       want: $3"; failures=$((failures + 1)); }
eq() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1" "$2" "$3"; fi; }

echo "== environment =="
echo "  uname: $(uname -sr)"
echo "  id: $(id)"
echo "  /dev/fuse: $(ls -l /dev/fuse 2>&1)"
echo "  fusermount3: $(command -v fusermount3 || echo none)"
echo "  fusermount: $(command -v fusermount || echo none)"
echo "  fuse.conf: $(cat /etc/fuse.conf 2>/dev/null | tr '\n' ' ' || echo none)"
echo "  fuse module: $(grep -c fuse /proc/filesystems 2>/dev/null || echo 0) entries"

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
  is_mounted "$MNT" && break
  sleep 0.1
done
if ! is_mounted "$MNT"; then
  echo "FAIL: mount did not come up"
  echo "--- diagnostics ---"
  echo "mount log size: $(wc -c <"$WORK/mount.log") bytes"
  echo "mock server alive: $(kill -0 "$server_pid" 2>/dev/null && echo yes || echo no)"
  ls -l /dev/fuse 2>&1 || echo "/dev/fuse MISSING"
  id
  command -v fusermount3 fusermount mountpoint 2>&1 || true
  echo "--- mountinfo for $MNT ---"
  grep -F " $MNT " /proc/self/mountinfo 2>/dev/null || echo "(not listed)"
  cat /proc/filesystems | grep -i fuse || echo "fuse not in /proc/filesystems"
  echo "--- mount log ---"
  tail -30 "$WORK/mount.log"
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

echo "== multipart upload >= 25 MB (obsfs threshold) =="
head -c 31457280 /dev/urandom >big.bin
eq "30 MiB md5" "$(md5sum big.bin | cut -d' ' -f1)" "$(md5sum <big.bin | cut -d' ' -f1)"

echo "== exact threshold boundary (26214400 = 25 MB) =="
head -c 26214400 /dev/urandom >exact.bin
eq "25 MiB threshold boundary md5" "$(md5sum exact.bin | cut -d' ' -f1)" "$(md5sum <exact.bin | cut -d' ' -f1)"

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
total=$(stat -f -c %b "$MNT")
blocksize=$(stat -f -c %S "$MNT")
total=$((total * blocksize))
avail_blocks=$(stat -f -c %a "$MNT")
avail=$((avail_blocks * blocksize))
if [ "${total:-0}" -gt 0 ] && [ "${avail:-0}" -gt 0 ]; then
  pass "df reports non-zero size (${total}B total, ${avail}B avail)"
else
  fail "df reports usable capacity" "total=$total avail=$avail" "both > 0"
fi
# `used` comes from OBS's bucket-wide figure, which is cached for 60 s, so it
# reflects whatever was uploaded before the first statfs call in this mount.
# Assert it is a sane number rather than a specific one.
used=$(stat -f -c %b "$MNT")
used=$(( used * blocksize ))
if [ "${used:-0}" -gt 0 ]; then
  pass "df reports non-zero used bytes"
else
  fail "df reports used bytes" "$used" "> 0"
fi
# The kernel may substitute its own FUSE default for f_namemax, so only
# assert that statvfs() itself works and reports the block size we set.
bsize=$(python3 -c "import os;print(os.statvfs('$MNT').f_frsize)")
eq "statvfs block size" "$bsize" "4096"

echo "== statfs matches obsfs (16 TiB ceiling) =="
# Huawei's obsfs fills f_blocks/f_bavail with 0xFFFFFFFF blocks of 4096 bytes.
same_as_obsfs=$((0xFFFFFFFF * 4096))
eq "synthetic capacity equals obsfs" "$total" "$same_as_obsfs"

echo "== unix metadata persistence (chmod/chown/touch) =="
echo meta >meta.txt
chmod 640 meta.txt
perms=$(stat -c %a meta.txt)
eq "chmod survives" "$perms" "640"
chown 1234:5678 meta.txt 2>/dev/null && {
  owner=$(stat -c '%u:%g' meta.txt)
  eq "chown survives" "$owner" "1234:5678"
} || echo "  skip chown (needs privileges)"
touch -d "2020-01-02 03:04:05 UTC" meta.txt
eq "utimes survives" "$(date -u -r meta.txt +%Y-%m-%d)" "2020-01-02"
# Re-stat from a different process to make sure nothing is just in-memory.
eq "chmod persists across processes" "$(stat -c %a meta.txt)" "640"

echo "== symlinks =="
echo target >real.txt
ln -s real.txt link.txt
eq "readlink" "$(readlink link.txt)" "real.txt"
eq "symlink target readable" "$(cat link.txt)" "target"

echo "== extended attributes =="
# Use an actual invocation rather than `command -v`: it succeeds for
# non-executable files too, which would make this guard useless.
have_xattr=0
if setfattr --version >/dev/null 2>&1 || getfattr --version >/dev/null 2>&1; then
  have_xattr=1
fi
if [ "${OBS_E2E_REQUIRE_XATTR:-0}" = "1" ] && [ "$have_xattr" = "0" ]; then
  # CI sets this so a missing `attr` package fails the build instead of
  # skipping -- a silently skipped branch is how the base64-padding bug
  # survived a whole round of "all tests pass".
  fail "xattr tools available" "setfattr missing" "install the attr package"
elif setfattr -n user.colour -v blue meta.txt 2>/dev/null; then
  eq "getfattr" "$(getfattr --only-values -n user.colour meta.txt 2>/dev/null)" "blue"
  eq "listxattr contains name" "$(getfattr -d meta.txt 2>/dev/null | grep -c user.colour)" "1"
  # A second attribute must not clobber the first.
  setfattr -n user.owner -v alice meta.txt 2>/dev/null
  eq "two xattrs coexist" "$(getfattr -d meta.txt 2>/dev/null | grep -c 'user\.')" "2"
  # Base64 padding must never reach a header name (regression).
  eq "xattr key is header-safe" \
    "$(getfattr -d meta.txt 2>/dev/null | grep -c 'xdg\.')" "0"
  setfattr -x user.colour meta.txt 2>/dev/null
  eq "removexattr" "$(getfattr -d meta.txt 2>/dev/null | grep -c user.colour)" "0"
  eq "missing xattr reports ENODATA" \
    "$(getfattr -n user.nope meta.txt 2>&1 >/dev/null | grep -c 'No such attribute')" "1"
else
  echo "  skip xattr (attr package missing)"
fi

echo "== every request must have carried a valid signature =="
stats=$(curl -sf "http://127.0.0.1:$PORT/__stats")
sigfail=$(printf '%s' "$stats" | sed -n 's/.*"signature_failures": \([0-9]*\).*/\1/p')
eq "signature failures" "${sigfail:-unknown}" "0"

cd "$WORK" || exit 1

# --- path-style endpoint (service endpoint + separate bucket) -------------
# obsfs takes a service endpoint and a bucket name; users coming from it will
# configure the same way, so this shape must work too.
echo "== path-style endpoint (service endpoint, no bucket in host) =="
PATH_MNT=$WORK/pathmnt
mkdir -p "$PATH_MNT"
cat >"$WORK/path.yaml" <<EOF
mountpoint: $PATH_MNT
bucket: test-bucket
endpoint: http://127.0.0.1:$PORT
ak: TESTAK
sk: TESTSK
EOF
chmod 600 "$WORK/path.yaml"
"$BIN" --config "$WORK/path.yaml" >"$WORK/path.log" 2>&1 &
path_pid=$!
for _ in $(seq 1 50); do
  is_mounted "$PATH_MNT" && break
  sleep 0.1
done
if is_mounted "$PATH_MNT"; then
  echo hello-path >"$PATH_MNT/p.txt"
  eq "path-style write/read" "$(cat "$PATH_MNT/p.txt")" "hello-path"
  fusermount3 -u "$PATH_MNT" 2>/dev/null || fusermount -u "$PATH_MNT" 2>/dev/null || umount -l "$PATH_MNT" 2>/dev/null
else
  fail "path-style mount" "not mounted" "mounted"
  tail -5 "$WORK/path.log"
fi
kill "$path_pid" 2>/dev/null

# --- a POSIX/file bucket must be refused, not silently misused ------------
echo "== refuses an OBS POSIX (file) bucket =="
for pid in $(pgrep -f "mock_obs[.]py $PORT" 2>/dev/null); do kill "$pid" 2>/dev/null; done
sleep 0.5
OBS_MOCK_BUCKET_TYPE=posix python3 "$REPO/tests/mock_obs.py" "$PORT" >"$WORK/server2.log" 2>&1 &
server_pid=$!
sleep 1.2
out=$("$BIN" --config "$CONF" 2>&1)
if printf '%s' "$out" | grep -qi "POSIX/file bucket"; then
  pass "file bucket rejected with an explanation"
else
  fail "file bucket rejected" "$(printf '%s' "$out" | head -3)" "mentions POSIX/file bucket"
fi

echo
if [ "$failures" -eq 0 ]; then
  echo "ALL PASSED"
else
  echo "$failures CHECK(S) FAILED"
  echo "--- mount log ---"; tail -30 "$WORK/mount.log"
  [ -f "$ACCESS" ] && { echo "--- requests ---"; tail -40 "$ACCESS"; }
fi
exit $((failures > 0))
