#!/usr/bin/env bash
set -euo pipefail

: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
: "${SOURCE_URL:?SOURCE_URL is required}"
: "${SOURCE_SHA256:?SOURCE_SHA256 is required}"

ROOT="$RUNNER_TEMP/validation"
ARCHIVE="$ROOT/source.zip"
EXTRACT="$ROOT/payload"
EVIDENCE="$ROOT/evidence"
DOCKER_IMAGE="validation-linux:${GITHUB_RUN_ID:-local}"

mkdir -p "$ROOT" "$EXTRACT" "$EVIDENCE"
chmod 700 "$ROOT"

case "$SOURCE_URL" in
  https://*) ;;
  *) echo "SOURCE_URL_INVALID"; exit 1 ;;
esac
if ! [[ "$SOURCE_SHA256" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "SOURCE_SHA256_INVALID"; exit 1
fi

download_error="$ROOT/download-error.txt"
if ! curl --fail --location --silent --show-error --max-redirs 5 \
    --proto '=https' --tlsv1.2 --output "$ARCHIVE" "$SOURCE_URL" 2>"$download_error"; then
  echo "SOURCE_DOWNLOAD_FAILED"; exit 1
fi
actual_hash="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
if [[ "${actual_hash,,}" != "${SOURCE_SHA256,,}" ]]; then
  echo "SOURCE_SHA256_MISMATCH"; exit 1
fi
unset SOURCE_URL SOURCE_SHA256

# Validate ZIP paths, duplicates, symlinks, entry count and total uncompressed size
# before extraction. Then check both source manifests against every file.
python3 - "$ARCHIVE" "$EXTRACT" <<'PY'
import hashlib, json, pathlib, stat, sys, zipfile
archive, destination = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
max_entries, max_total = 10000, 2 * 1024 * 1024 * 1024
seen, total = set(), 0
with zipfile.ZipFile(archive) as z:
    infos = z.infolist()
    if not infos or len(infos) > max_entries:
        raise SystemExit("ARCHIVE_ENTRY_COUNT_INVALID")
    for item in infos:
        p = pathlib.PurePosixPath(item.filename)
        if p.is_absolute() or ".." in p.parts or not p.parts:
            raise SystemExit("ARCHIVE_PATH_INVALID")
        norm = str(p)
        if norm in seen:
            raise SystemExit("ARCHIVE_DUPLICATE_PATH")
        seen.add(norm)
        mode = (item.external_attr >> 16) & 0xffff
        if stat.S_ISLNK(mode):
            raise SystemExit("ARCHIVE_SYMLINK_REJECTED")
        total += item.file_size
        if total > max_total or item.file_size > 256 * 1024 * 1024:
            raise SystemExit("ARCHIVE_EXPANSION_LIMIT")
    if z.testzip() is not None:
        raise SystemExit("ARCHIVE_CRC_FAILURE")
    z.extractall(destination)

roots = []
for cmake in destination.rglob("CMakeLists.txt"):
    base = cmake.parent
    if all((base / name).is_dir() for name in ("src","include","tests")):
        roots.append(base)
if len(roots) != 1:
    raise SystemExit("PACKAGE_BUILD_ROOT_LAYOUT_INVALID")
source = roots[0]

def verify_manifest(path, root, expected_count=None):
    doc = json.loads(path.read_text(encoding="utf-8"))
    rows = doc.get("files")
    if not isinstance(rows, list) or (expected_count is not None and len(rows) != expected_count):
        raise SystemExit("MANIFEST_ENTRY_COUNT_INVALID")
    for row in rows:
        rel = pathlib.PurePosixPath(row["path"])
        if rel.is_absolute() or ".." in rel.parts:
            raise SystemExit("MANIFEST_PATH_INVALID")
        file = root.joinpath(*rel.parts)
        if not file.is_file():
            raise SystemExit("MANIFEST_FILE_MISSING")
        data = file.read_bytes()
        if len(data) != int(row["size_bytes"]) or hashlib.sha256(data).hexdigest() != row["sha256"]:
            raise SystemExit("MANIFEST_FILE_HASH_MISMATCH")
    return doc

payload = verify_manifest(source / "SOURCE_SHA256_MANIFEST.json", source, 933)
if payload.get("revision") != "R5_FIX3_PROCESS_RUNNER_HARDENING_20261127":
    raise SystemExit("CANDIDATE_REVISION_MISMATCH")
if payload.get("baseline_sha256") != "2939a1bbae31367d972e75f292648a68b0b5afddc0b793d0b55583fd368e318d":
    raise SystemExit("BASELINE_IDENTITY_MISMATCH")
print("SOURCE_MANIFEST_933_OF_933_PASS")
PY

source_root="$(find "$EXTRACT" -type f -name CMakeLists.txt -printf '%h\n' | while read -r d; do
  if [[ -d "$d/src" && -d "$d/include" && -d "$d/tests" ]]; then echo "$d"; fi
done)"
if [[ -z "$source_root" ]]; then echo "PACKAGE_BUILD_ROOT_LAYOUT_INVALID"; exit 1; fi
rm -f "$ARCHIVE" "$download_error"

# The Docker image is built before Candidate execution. Candidate has no network,
# no secrets, a read-only source mount, bounded tmpfs workspaces and cgroup limits.
docker build --quiet -t "$DOCKER_IMAGE" "$RUNNER_TEMP/docker-context"
container_id="$(docker create \
  --network none --read-only \
  --memory 6g --memory-swap 6g --cpus 2 --pids-limit 256 \
  --cap-drop ALL --security-opt no-new-privileges \
  --user 65532:65532 \
  --tmpfs /tmp:rw,nosuid,nodev,size=512m,uid=65532,gid=65532,mode=1777 \
  --tmpfs /build-on:rw,nosuid,nodev,size=3g,uid=65532,gid=65532,mode=1777 \
  --tmpfs /build-off:rw,nosuid,nodev,size=1g,uid=65532,gid=65532,mode=1777 \
  --tmpfs /build-san:rw,nosuid,nodev,size=3g,uid=65532,gid=65532,mode=1777 \
  --tmpfs /evidence:rw,nosuid,nodev,size=256m,uid=65532,gid=65532,mode=1777 \
  --mount "type=bind,src=$source_root,dst=/src,readonly" \
  "$DOCKER_IMAGE")"
set +e
docker start --attach "$container_id" >/dev/null 2>&1
container_exit=$?
set -e

mkdir -p "$EVIDENCE"
if ! docker cp "$container_id:/evidence/." "$EVIDENCE/" >/dev/null 2>&1; then
  printf '%s\n' '{"status":"EVIDENCE_COPY_FAILED"}' > "$EVIDENCE/execution-result.json"
  container_exit=1
fi
docker rm "$container_id" >/dev/null 2>&1 || true
docker image rm "$DOCKER_IMAGE" >/dev/null 2>&1 || true

python3 - "$EVIDENCE/execution-result.json" "$actual_hash" "$container_exit" <<'PY'
import json, pathlib, sys
p, source_sha, exit_code = pathlib.Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])
try: doc=json.loads(p.read_text())
except Exception: doc={"stages":{}}
doc["source_archive_sha256"]=source_sha
doc["candidate_revision"]="R5_FIX3_PROCESS_RUNNER_HARDENING_20261127"
doc["runner_os"]="ubuntu-24.04"
doc["container_exit_code"]=exit_code
doc["status"]="PASS" if exit_code == 0 else "FAIL"
p.write_text(json.dumps(doc,indent=2)+"\n")
PY

echo "status=$([[ $container_exit -eq 0 ]] && echo PASS || echo FAIL)" >> "$GITHUB_OUTPUT"
if [[ "$container_exit" -ne 0 ]]; then
  echo "CANDIDATE_LINUX_VALIDATION_REQUIRES_REVIEW"
  exit 1
fi
echo "CANDIDATE_LINUX_VALIDATION_COMPLETED"
