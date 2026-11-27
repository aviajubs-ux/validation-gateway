#!/usr/bin/env bash
set -uo pipefail

SOURCE_ROOT=/src
if [[ $# -ge 1 ]]; then SOURCE_ROOT="$1"; fi
EVIDENCE_ROOT=/evidence
BUILD_ON=/build-on
BUILD_OFF=/build-off
BUILD_SAN=/build-san

mkdir -p "$EVIDENCE_ROOT" "$BUILD_ON" "$BUILD_OFF" "$BUILD_SAN" /tmp/uce-validation
chmod 700 /tmp/uce-validation 2>/dev/null || true

CONFIGURE_ON=NOT_RUN
BUILD_ON_STATUS=NOT_RUN
CTEST_ON=NOT_RUN
CONFIGURE_OFF=NOT_RUN
OFF_GATE=NOT_RUN
BUILD_OFF_STATUS=NOT_RUN
CONFIGURE_SAN=NOT_RUN
BUILD_SAN_STATUS=NOT_RUN
CTEST_SAN=NOT_RUN

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
  local key="$1"
  shift
  local log="$EVIDENCE_ROOT/$key.log"
  "$@" >"$log" 2>&1
}

check_junit_no_skip() {
  local xml="$1"
  python3 - "$xml" <<'PYJUNIT'
import sys
import xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
counts = {key: sum(int(s.attrib.get(key, "0")) for s in suites)
          for key in ("tests", "failures", "errors", "skipped")}
print("JUNIT_COUNTS", counts)
sys.exit(0 if counts["tests"] > 0 and counts["failures"] == 0
         and counts["errors"] == 0 and counts["skipped"] == 0 else 1)
PYJUNIT
}

if run_logged configure-on cmake -S "$SOURCE_ROOT" -B "$BUILD_ON" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DUCE_BUILD_TESTS=ON -DBUILD_TESTING=ON; then
  CONFIGURE_ON=PASS
  if run_logged build-on cmake --build "$BUILD_ON" --parallel 2; then
    BUILD_ON_STATUS=PASS
    if run_logged discovery-on ctest --test-dir "$BUILD_ON" -N; then
      if run_logged ctest-on ctest --test-dir "$BUILD_ON" --output-on-failure \
          --verbose --parallel 2 --timeout 300 \
          --output-junit "$EVIDENCE_ROOT/ctest-linux.xml"; then
        if check_junit_no_skip "$EVIDENCE_ROOT/ctest-linux.xml" >"$EVIDENCE_ROOT/ctest-counts.txt" 2>&1; then
          CTEST_ON=PASS
        else
          CTEST_ON=FAIL_OR_SKIP
        fi
      else
        CTEST_ON=FAIL
      fi
    else
      CTEST_ON=FAIL_DISCOVERY
    fi
  else
    BUILD_ON_STATUS=FAIL
  fi
else
  CONFIGURE_ON=FAIL
fi

if run_logged configure-off cmake -S "$SOURCE_ROOT" -B "$BUILD_OFF" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DUCE_BUILD_TESTS=OFF -DBUILD_TESTING=OFF; then
  CONFIGURE_OFF=PASS
  if find "$BUILD_OFF" -name CTestTestfile.cmake -print -quit | grep -q .; then
    OFF_GATE=FAIL_CTEST_REGISTRATION_PRESENT
  elif ! cmake --build "$BUILD_OFF" --target help >"$EVIDENCE_ROOT/off-targets.log" 2>&1; then
    OFF_GATE=FAIL_TARGET_DISCOVERY
  elif grep -Fq 'uce_science_operations_tests' "$EVIDENCE_ROOT/off-targets.log"; then
    OFF_GATE=FAIL_TEST_TARGET_PRESENT
  else
    OFF_GATE=PASS
  fi
  if run_logged build-off cmake --build "$BUILD_OFF" --parallel 2; then
    BUILD_OFF_STATUS=PASS
  else
    BUILD_OFF_STATUS=FAIL
  fi
else
  CONFIGURE_OFF=FAIL
fi

if run_logged configure-sanitizers cmake -S "$SOURCE_ROOT" -B "$BUILD_SAN" -G Ninja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo -DUCE_BUILD_TESTS=ON -DBUILD_TESTING=ON \
    -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"; then
  CONFIGURE_SAN=PASS
  if run_logged build-sanitizers cmake --build "$BUILD_SAN" \
      --target uce_science_operations_tests --parallel 2; then
    BUILD_SAN_STATUS=PASS
    if ASAN_OPTIONS="detect_leaks=1:halt_on_error=1" \
       UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" \
       ctest --test-dir "$BUILD_SAN" -R '^uce_science_operations_tests$' \
         --output-on-failure --verbose --timeout 300 \
         --output-junit "$EVIDENCE_ROOT/ctest-sanitizers.xml" \
         >"$EVIDENCE_ROOT/ctest-sanitizers.log" 2>&1; then
      if check_junit_no_skip "$EVIDENCE_ROOT/ctest-sanitizers.xml" \
          >"$EVIDENCE_ROOT/ctest-sanitizer-counts.txt" 2>&1; then
        CTEST_SAN=PASS
      else
        CTEST_SAN=FAIL_OR_SKIP
      fi
    else
      CTEST_SAN=FAIL
    fi
  else
    BUILD_SAN_STATUS=FAIL
  fi
else
  CONFIGURE_SAN=FAIL
fi

{
  printf 'configure_on=%s\n' "$CONFIGURE_ON"
  printf 'build_on=%s\n' "$BUILD_ON_STATUS"
  printf 'ctest_on=%s\n' "$CTEST_ON"
  printf 'configure_off=%s\n' "$CONFIGURE_OFF"
  printf 'off_gate=%s\n' "$OFF_GATE"
  printf 'build_off=%s\n' "$BUILD_OFF_STATUS"
  printf 'configure_sanitizers=%s\n' "$CONFIGURE_SAN"
  printf 'build_sanitizers=%s\n' "$BUILD_SAN_STATUS"
  printf 'ctest_sanitizers=%s\n' "$CTEST_SAN"
} > "$EVIDENCE_ROOT/stages.env"

python3 - "$EVIDENCE_ROOT" <<'PYSUMMARY'
import json, pathlib, sys, xml.etree.ElementTree as ET
root = pathlib.Path(sys.argv[1])
results = {}
for filename in ("toolchain.txt", "stages.env"):
    for line in (root / filename).read_text(errors="replace").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            results[key] = value
summary = {"schema":"validation.gateway.linux_candidate_result.v1", "stages":results}
for filename, key in (("ctest-linux.xml","ctest_on_counts"),
                      ("ctest-sanitizers.xml","ctest_sanitizers_counts")):
    path = root / filename
    if path.exists():
        tree = ET.parse(path).getroot()
        suites = [tree] if tree.tag == "testsuite" else list(tree.iter("testsuite"))
        summary[key] = {
            "tests": sum(int(s.attrib.get("tests","0")) for s in suites),
            "failures": sum(int(s.attrib.get("failures","0")) for s in suites),
            "errors": sum(int(s.attrib.get("errors","0")) for s in suites),
            "skipped": sum(int(s.attrib.get("skipped","0")) for s in suites)
        }
(root / "execution-result.json").write_text(json.dumps(summary, indent=2) + "\n")
PYSUMMARY

OVERALL=PASS
for status in "$CONFIGURE_ON" "$BUILD_ON_STATUS" "$CTEST_ON" \
    "$CONFIGURE_OFF" "$OFF_GATE" "$BUILD_OFF_STATUS" \
    "$CONFIGURE_SAN" "$BUILD_SAN_STATUS" "$CTEST_SAN"; do
  if [[ "$status" != PASS ]]; then OVERALL=FAIL; fi
done
printf '%s\n' "$OVERALL" > "$EVIDENCE_ROOT/status.txt"
if [[ "$OVERALL" == PASS ]]; then exit 0; fi
exit 1
