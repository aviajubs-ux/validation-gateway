#!/usr/bin/env bash
set -uo pipefail

SOURCE_ROOT="${1:-/src}"
EVIDENCE_ROOT="/evidence"
BUILD_ON="/build-on"
BUILD_OFF="/build-off"
BUILD_SAN="/build-san"

mkdir -p "$EVIDENCE_ROOT" "$BUILD_ON" "$BUILD_OFF" "$BUILD_SAN" /tmp/uce-validation
chmod 700 /tmp/uce-validation 2>/dev/null || true

declare -A RESULT
RESULT[configure_on]="NOT_RUN"
RESULT[build_on]="NOT_RUN"
RESULT[ctest_on]="NOT_RUN"
RESULT[configure_off]="NOT_RUN"
RESULT[off_gate]="NOT_RUN"
RESULT[build_off]="NOT_RUN"
RESULT[configure_sanitizers]="NOT_RUN"
RESULT[build_sanitizers]="NOT_RUN"
RESULT[ctest_sanitizers]="NOT_RUN"

{
  echo "runner_os=Ubuntu 24.04 container"
  echo "cmake=$(cmake --version | head -n 1)"
  echo "compiler=$(c++ --version | head -n 1)"
  echo "python=$(python3 --version 2>&1)"
  echo "cpu_limit=2"
  echo "memory_limit=6GiB"
  echo "pids_limit=256"
  echo "network=disabled"
  echo "source_root=/src"
} > "$EVIDENCE_ROOT/toolchain.txt"

run_logged() {
  local key="$1"; shift
  local log="$EVIDENCE_ROOT/$key.log"
  "$@" >"$log" 2>&1
  return $?
}

if run_logged configure_on cmake -S "$SOURCE_ROOT" -B "$BUILD_ON" -G Ninja -DCMAKE_BUILD_TYPE=Release -DUCE_BUILD_TESTS=ON -DBUILD_TESTING=ON; then
  RESULT[configure_on]="PASS"
  if run_logged build_on cmake --build "$BUILD_ON" --parallel 2; then
    RESULT[build_on]="PASS"
    if run_logged discovery_on ctest --test-dir "$BUILD_ON" -N; then
      if run_logged ctest_on ctest --test-dir "$BUILD_ON" --output-on-failure --verbose --parallel 2 --timeout 300 --output-junit "$EVIDENCE_ROOT/ctest-linux.xml"; then
        if python3 - "$EVIDENCE_ROOT/ctest-linux.xml" <<'PYCTEST'
import sys, xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
counts = {k: sum(int(s.attrib.get(k, "0")) for s in suites) for k in ("tests","failures","errors","skipped")}
print("CTEST_COUNTS", counts)
sys.exit(0 if counts["tests"] > 0 and counts["failures"] == 0 and counts["errors"] == 0 and counts["skipped"] == 0 else 1)
PYCTEST
        then
          RESULT[ctest_on]="PASS"
        else
          RESULT[ctest_on]="FAIL_OR_SKIP"
        fi
      else
        RESULT[ctest_on]="FAIL"
      fi
    else
      RESULT[ctest_on]="FAIL_DISCOVERY"
    fi
  else
    RESULT[build_on]="FAIL"
  fi
else
  RESULT[configure_on]="FAIL"
fi

if run_logged configure_off cmake -S "$SOURCE_ROOT" -B "$BUILD_OFF" -G Ninja -DCMAKE_BUILD_TYPE=Release -DUCE_BUILD_TESTS=OFF -DBUILD_TESTING=OFF; then
  RESULT[configure_off]="PASS"
  if find "$BUILD_OFF" -name CTestTestfile.cmake -print -quit | grep -q .; then
    RESULT[off_gate]="FAIL_CTEST_REGISTRATION_PRESENT"
  elif ! cmake --build "$BUILD_OFF" --target help >"$EVIDENCE_ROOT/off-targets.log" 2>&1; then
    RESULT[off_gate]="FAIL_TARGET_DISCOVERY"
  elif grep -Fq 'uce_science_operations_tests' "$EVIDENCE_ROOT/off-targets.log"; then
    RESULT[off_gate]="FAIL_TEST_TARGET_PRESENT"
  else
    RESULT[off_gate]="PASS"
  fi
  if run_logged build_off cmake --build "$BUILD_OFF" --parallel 2; then
    RESULT[build_off]="PASS"
  else
    RESULT[build_off]="FAIL"
  fi
else
  RESULT[configure_off]="FAIL"
  RESULT[off_gate]="NOT_RUN"
  RESULT[build_off]="NOT_RUN"
fi

if run_logged configure_sanitizers cmake -S "$SOURCE_ROOT" -B "$BUILD_SAN" -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DUCE_BUILD_TESTS=ON -DBUILD_TESTING=ON -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"; then
  RESULT[configure_sanitizers]="PASS"
  if run_logged build_sanitizers cmake --build "$BUILD_SAN" --target uce_science_operations_tests --parallel 2; then
    RESULT[build_sanitizers]="PASS"
    if ASAN_OPTIONS="detect_leaks=1:halt_on_error=1" UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" ctest --test-dir "$BUILD_SAN" -R '^uce_science_operations_tests
  else
    RESULT[build_sanitizers]="FAIL"
  fi
else
  RESULT[configure_sanitizers]="FAIL"
fi

{
  printf 'configure_on=%s\n' "${RESULT[configure_on]}" 
  printf 'build_on=%s\n' "${RESULT[build_on]}"
  printf 'ctest_on=%s\n' "${RESULT[ctest_on]}"
  printf 'configure_off=%s\n' "${RESULT[configure_off]}"
  printf 'off_gate=%s\n' "${RESULT[off_gate]}"
  printf 'build_off=%s\n' "${RESULT[build_off]}"
  printf 'configure_sanitizers=%s\n' "${RESULT[configure_sanitizers]}"
  printf 'build_sanitizers=%s\n' "${RESULT[build_sanitizers]}"
  printf 'ctest_sanitizers=%s\n' "${RESULT[ctest_sanitizers]}"
} > "$EVIDENCE_ROOT/stages.env"

python3 - "$EVIDENCE_ROOT" <<'PY'
import json, pathlib, sys, xml.etree.ElementTree as ET
root = pathlib.Path(sys.argv[1])
results = {}
for line in (root / "toolchain.txt").read_text(errors="replace").splitlines():
    if "=" in line:
        k, v = line.split("=", 1)
        results[k] = v
for line in (root / "stages.env").read_text(errors="replace").splitlines():
    if "=" in line:
        k, v = line.split("=", 1)
        results[k] = v
summary = {"schema":"validation.gateway.linux_candidate_result.v1", "stages":results}
for name, target in (("ctest-linux.xml","ctest_on_counts"),("ctest-sanitizers.xml","ctest_sanitizers_counts")):
    p = root / name
    if p.exists():
        try:
            tree = ET.parse(p).getroot()
            suites = [tree] if tree.tag == "testsuite" else list(tree.iter("testsuite"))
            summary[target] = {
                "tests": sum(int(s.attrib.get("tests","0")) for s in suites),
                "failures": sum(int(s.attrib.get("failures","0")) for s in suites),
                "errors": sum(int(s.attrib.get("errors","0")) for s in suites),
                "skipped": sum(int(s.attrib.get("skipped","0")) for s in suites),
            }
        except Exception as exc:
            summary[target] = {"parse_error":type(exc).__name__}
(root / "execution-result.json").write_text(json.dumps(summary, indent=2) + "\n")
PY

overall="PASS"
for key in configure_on build_on ctest_on configure_off off_gate build_off configure_sanitizers build_sanitizers ctest_sanitizers; do
  value="${RESULT[$key]}"
  if [[ "$value" != "PASS" ]]; then overall="FAIL"; fi
done
printf '%s\n' "$overall" > "$EVIDENCE_ROOT/status.txt"
if [[ "$overall" == "PASS" ]]; then exit 0; fi
exit 1
 --output-on-failure --verbose --timeout 300 --output-junit "$EVIDENCE_ROOT/ctest-sanitizers.xml" >"$EVIDENCE_ROOT/ctest-sanitizers.log" 2>&1; then
      if python3 - "$EVIDENCE_ROOT/ctest-sanitizers.xml" <<'PYCTEST'
import sys, xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
counts = {k: sum(int(s.attrib.get(k, "0")) for s in suites) for k in ("tests","failures","errors","skipped")}
print("SANITIZER_CTEST_COUNTS", counts)
sys.exit(0 if counts["tests"] > 0 and counts["failures"] == 0 and counts["errors"] == 0 and counts["skipped"] == 0 else 1)
PYCTEST
      then
        RESULT[ctest_sanitizers]="PASS"
      else
        RESULT[ctest_sanitizers]="FAIL_OR_SKIP"
      fi
    else
      RESULT[ctest_sanitizers]="FAIL"
    fi
  else
    RESULT[build_sanitizers]="FAIL"
  fi
else
  RESULT[configure_sanitizers]="FAIL"
fi

{
  printf 'configure_on=%s\n' "${RESULT[configure_on]}" 
  printf 'build_on=%s\n' "${RESULT[build_on]}"
  printf 'ctest_on=%s\n' "${RESULT[ctest_on]}"
  printf 'configure_off=%s\n' "${RESULT[configure_off]}"
  printf 'off_gate=%s\n' "${RESULT[off_gate]}"
  printf 'build_off=%s\n' "${RESULT[build_off]}"
  printf 'configure_sanitizers=%s\n' "${RESULT[configure_sanitizers]}"
  printf 'build_sanitizers=%s\n' "${RESULT[build_sanitizers]}"
  printf 'ctest_sanitizers=%s\n' "${RESULT[ctest_sanitizers]}"
} > "$EVIDENCE_ROOT/stages.env"

python3 - "$EVIDENCE_ROOT" <<'PY'
import json, pathlib, sys, xml.etree.ElementTree as ET
root = pathlib.Path(sys.argv[1])
results = {}
for line in (root / "toolchain.txt").read_text(errors="replace").splitlines():
    if "=" in line:
        k, v = line.split("=", 1)
        results[k] = v
for line in (root / "stages.env").read_text(errors="replace").splitlines():
    if "=" in line:
        k, v = line.split("=", 1)
        results[k] = v
summary = {"schema":"validation.gateway.linux_candidate_result.v1", "stages":results}
for name, target in (("ctest-linux.xml","ctest_on_counts"),("ctest-sanitizers.xml","ctest_sanitizers_counts")):
    p = root / name
    if p.exists():
        try:
            tree = ET.parse(p).getroot()
            suites = [tree] if tree.tag == "testsuite" else list(tree.iter("testsuite"))
            summary[target] = {
                "tests": sum(int(s.attrib.get("tests","0")) for s in suites),
                "failures": sum(int(s.attrib.get("failures","0")) for s in suites),
                "errors": sum(int(s.attrib.get("errors","0")) for s in suites),
                "skipped": sum(int(s.attrib.get("skipped","0")) for s in suites),
            }
        except Exception as exc:
            summary[target] = {"parse_error":type(exc).__name__}
(root / "execution-result.json").write_text(json.dumps(summary, indent=2) + "\n")
PY

overall="PASS"
for key in configure_on build_on ctest_on configure_off off_gate build_off configure_sanitizers build_sanitizers ctest_sanitizers; do
  value="${RESULT[$key]}"
  if [[ "$value" != "PASS" ]]; then overall="FAIL"; fi
done
printf '%s\n' "$overall" > "$EVIDENCE_ROOT/status.txt"
if [[ "$overall" == "PASS" ]]; then exit 0; fi
exit 1
