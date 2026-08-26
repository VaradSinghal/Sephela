#!/bin/bash
# =============================================================================
# Sephela Sandbox Runner — Orchestrates dynamic analysis in an isolated
# Android emulator with Frida instrumentation and network capture.
#
# SECURITY MODEL:
#   - Runs inside a Docker container with KVM passthrough (no host access)
#   - Network egress is DEFAULT DENY (iptables rules below)
#   - DNS is proxied through a controlled resolver
#   - The emulator snapshot is EPHEMERAL — destroyed after each run
#   - All artifacts are written to a bind-mounted output directory
#
# REQUIREMENTS:
#   - Linux host with KVM enabled (WSL2 with nested virt or bare metal)
#   - Docker with --privileged or --device=/dev/kvm
#   - Android SDK command-line tools (avdmanager, emulator, adb)
#   - Frida server binary for the target architecture
#   - tcpdump
#
# USAGE:
#   ./run_analysis.sh <apk_path> <output_dir> [--timeout 180] [--api-level 33]
#
# OUTPUT (written to <output_dir>/):
#   metadata.json      — sandbox run metadata
#   frida_trace.json   — Frida hook log
#   network.json       — parsed network connections
#   logcat.json        — structured logcat output
#   raw/capture.pcap   — raw packet capture (if tcpdump available)
#   raw/logcat.txt     — raw logcat text
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

APK_PATH="${1:?Usage: $0 <apk_path> <output_dir> [--timeout N] [--api-level N]}"
OUTPUT_DIR="${2:?Usage: $0 <apk_path> <output_dir> [--timeout N] [--api-level N]}"
TIMEOUT_SECS=180
API_LEVEL=33
FRIDA_SCRIPT="$(dirname "$0")/frida_hooks.js"
SANDBOX_ID="sandbox-$(date +%s)-$$"

# Parse optional args
shift 2
while [[ $# -gt 0 ]]; do
    case "$1" in
        --timeout)  TIMEOUT_SECS="$2"; shift 2 ;;
        --api-level) API_LEVEL="$2"; shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------

mkdir -p "${OUTPUT_DIR}/raw"

# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] [sandbox] $*"; }
cleanup() {
    log "Cleaning up..."
    # Kill background processes
    [[ -n "${TCPDUMP_PID:-}" ]] && kill "$TCPDUMP_PID" 2>/dev/null || true
    [[ -n "${LOGCAT_PID:-}" ]] && kill "$LOGCAT_PID" 2>/dev/null || true
    [[ -n "${FRIDA_PID:-}" ]] && kill "$FRIDA_PID" 2>/dev/null || true
    # Kill emulator
    adb -s emulator-5554 emu kill 2>/dev/null || true
    log "Cleanup complete."
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Step 1: Compute APK hash and package name
# ---------------------------------------------------------------------------

log "Step 1: Computing APK metadata..."
APK_SHA256=$(sha256sum "$APK_PATH" | awk '{print $1}')
# Extract package name from APK using aapt2 (from SDK build-tools)
AAPT2=$(find "${ANDROID_HOME}/build-tools" -name aapt2 -type f 2>/dev/null | head -1)
if [[ -n "$AAPT2" ]]; then
    APK_PACKAGE=$("$AAPT2" dump badging "$APK_PATH" 2>/dev/null | sed -n "s/^package: name='\([^']*\)'.*/\1/p" | head -1)
fi
# Fallback: use aapt if aapt2 didn't work
if [[ -z "$APK_PACKAGE" ]]; then
    AAPT=$(find "${ANDROID_HOME}/build-tools" -name aapt -type f 2>/dev/null | head -1)
    if [[ -n "$AAPT" ]]; then
        APK_PACKAGE=$("$AAPT" dump badging "$APK_PATH" 2>/dev/null | sed -n "s/^package: name='\([^']*\)'.*/\1/p" | head -1)
    fi
fi
APK_PACKAGE="${APK_PACKAGE:-unknown}"
log "  SHA256: ${APK_SHA256}"
log "  Package: ${APK_PACKAGE}"

# ---------------------------------------------------------------------------
# Step 2: Network isolation (CRITICAL SECURITY CONTROL)
# ---------------------------------------------------------------------------

log "Step 2: Configuring network isolation..."
# Default-deny all outbound from the emulator's virtual interface.
# Only allow DNS to our controlled resolver and loopback.
# This prevents real C2 communication while still capturing DNS queries.
iptables -F SANDBOX_EGRESS 2>/dev/null || iptables -N SANDBOX_EGRESS
iptables -A SANDBOX_EGRESS -o lo -j ACCEPT
iptables -A SANDBOX_EGRESS -p udp --dport 53 -d 127.0.0.1 -j ACCEPT  # local DNS
iptables -A SANDBOX_EGRESS -p tcp --dport 53 -d 127.0.0.1 -j ACCEPT
iptables -A SANDBOX_EGRESS -j LOG --log-prefix "[sephela-sandbox-blocked] "
iptables -A SANDBOX_EGRESS -j DROP
# Apply to the emulator's outbound traffic
iptables -I OUTPUT -m owner --uid-owner "$(id -u)" -j SANDBOX_EGRESS
log "  Egress: DEFAULT DENY (DNS to localhost only)"

# ---------------------------------------------------------------------------
# Step 3: Boot emulator
# ---------------------------------------------------------------------------

log "Step 3: Booting Android emulator (API ${API_LEVEL})..."
AVD_NAME="sephela_sandbox_api${API_LEVEL}"

# Copy AVD from build-time template into the runtime volume.
# /root/.android is a Docker volume (for statvfs compatibility with the
# emulator's disk space check), so the build-time AVD isn't visible.
if [[ -d /opt/avd-template ]] && [[ ! -d /root/.android/avd ]]; then
    log "  Copying AVD template to runtime volume..."
    cp -a /opt/avd-template/* /root/.android/
fi

# Clean up any stale lock files from previous crashed runs
find /root/.android/avd/ -name "*.lock" -delete 2>/dev/null || true

# Create AVD if it doesn't exist
if ! avdmanager list avd 2>/dev/null | grep -q "$AVD_NAME"; then
    log "  Creating AVD: ${AVD_NAME}..."
    echo "no" | avdmanager create avd \
        --name "$AVD_NAME" \
        --package "system-images;android-${API_LEVEL};google_apis;x86_64" \
        --device "pixel_6" \
        --force
fi

# Boot emulator headless with snapshot
# ANDROID_EMULATOR_SKIP_DISK_CHECK bypasses the false-positive disk space check on tmpfs
export ANDROID_EMULATOR_SKIP_DISK_CHECK=1
emulator -avd "$AVD_NAME" \
    -no-window -no-audio -no-boot-anim \
    -gpu swiftshader_indirect \
    -no-snapshot \
    -wipe-data \
    -skip-adb-auth \
    -no-metrics \
    &
EMULATOR_PID=$!

# Wait for boot (with timeout)
log "  Waiting for emulator to boot..."
if ! timeout 120 adb wait-for-device; then
    log "  ERROR: adb wait-for-device timed out because emulator crashed."
    exit 1
fi
BOOT_TIMEOUT=120
BOOT_ELAPSED=0
while [[ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" != "1" ]]; do
    sleep 2
    BOOT_ELAPSED=$((BOOT_ELAPSED + 2))
    if [[ $BOOT_ELAPSED -ge $BOOT_TIMEOUT ]]; then
        log "  ERROR: Emulator failed to boot within ${BOOT_TIMEOUT}s"
        exit 1
    fi
done
log "  Emulator booted in ~${BOOT_ELAPSED}s."

# Record start time
START_TIME=$(date +%s%3N)

# ---------------------------------------------------------------------------
# Step 4: Start packet capture
# ---------------------------------------------------------------------------

log "Step 4: Starting packet capture..."
tcpdump -i any -w "${OUTPUT_DIR}/raw/capture.pcap" -c 100000 &
TCPDUMP_PID=$!

# ---------------------------------------------------------------------------
# Step 5: Start logcat capture
# ---------------------------------------------------------------------------

log "Step 5: Starting logcat capture..."
adb logcat -v threadtime > "${OUTPUT_DIR}/raw/logcat.txt" &
LOGCAT_PID=$!

# ---------------------------------------------------------------------------
# Step 6: Install and launch the APK
# ---------------------------------------------------------------------------

log "Step 6: Installing APK..."
adb install -r -t "$APK_PATH"

log "Step 6b: Launching APK (${APK_PACKAGE})..."
adb shell monkey -p "$APK_PACKAGE" -c android.intent.category.LAUNCHER 1

# ---------------------------------------------------------------------------
# Step 7: Inject Frida hooks
# ---------------------------------------------------------------------------

log "Step 7: Starting Frida instrumentation..."
if [[ -f "$FRIDA_SCRIPT" ]]; then
    # Push frida-server to device (assumes it's already in the container)
    FRIDA_SERVER="/data/local/tmp/frida-server"
    if ! adb shell "test -f $FRIDA_SERVER"; then
        log "  Pushing frida-server to device..."
        adb push /opt/frida/frida-server "$FRIDA_SERVER"
        adb shell "chmod 755 $FRIDA_SERVER"
    fi

    # Start frida-server on device
    adb shell "$FRIDA_SERVER -D &" 2>/dev/null &
    sleep 2

    # Run Frida script
    frida -U -n "$APK_PACKAGE" -l "$FRIDA_SCRIPT" \
        --no-pause \
        -o "${OUTPUT_DIR}/raw/frida_raw.json" \
        &
    FRIDA_PID=$!
    log "  Frida hooks injected."
else
    log "  WARNING: Frida script not found at ${FRIDA_SCRIPT}"
fi

# ---------------------------------------------------------------------------
# Step 8: UI interaction (monkey test)
# ---------------------------------------------------------------------------

log "Step 8: Running UI interaction (monkey, ${TIMEOUT_SECS}s timeout)..."
timeout "${TIMEOUT_SECS}" adb shell monkey \
    -p "$APK_PACKAGE" \
    --throttle 300 \
    --ignore-crashes \
    --ignore-timeouts \
    --ignore-security-exceptions \
    -v 2000 \
    2>/dev/null || true

# ---------------------------------------------------------------------------
# Step 9: Collect artifacts
# ---------------------------------------------------------------------------

log "Step 9: Collecting artifacts..."
END_TIME=$(date +%s%3N)
DURATION_MS=$((END_TIME - START_TIME))

# Kill background processes to flush buffers
kill "$LOGCAT_PID" 2>/dev/null || true
kill "$TCPDUMP_PID" 2>/dev/null || true
kill "$FRIDA_PID" 2>/dev/null || true
sleep 1

# Convert raw logcat to JSON
python3 "$(dirname "$0")/scripts/logcat_to_json.py" \
    "${OUTPUT_DIR}/raw/logcat.txt" \
    "${OUTPUT_DIR}/logcat.json" 2>/dev/null || true

# Convert raw Frida output to structured JSON
python3 "$(dirname "$0")/scripts/frida_to_json.py" \
    "${OUTPUT_DIR}/raw/frida_raw.json" \
    "${OUTPUT_DIR}/frida_trace.json" 2>/dev/null || true

# Parse PCAP to JSON (network.json)
python3 "$(dirname "$0")/scripts/pcap_to_json.py" \
    "${OUTPUT_DIR}/raw/capture.pcap" \
    "${OUTPUT_DIR}/network.json" 2>/dev/null || true

# Write metadata
FRIDA_VERSION=$(frida --version 2>/dev/null || echo "unknown")
cat > "${OUTPUT_DIR}/metadata.json" <<EOF
{
    "sandbox_id": "${SANDBOX_ID}",
    "emulator_image": "android-api-${API_LEVEL}-x86_64",
    "android_api_level": ${API_LEVEL},
    "duration_ms": ${DURATION_MS},
    "apk_sha256": "${APK_SHA256}",
    "apk_package": "${APK_PACKAGE}",
    "frida_version": "${FRIDA_VERSION}",
    "network_isolated": true,
    "exit_reason": "completed"
}
EOF

log "Step 9: Artifacts written to ${OUTPUT_DIR}"
log "  Duration: ${DURATION_MS}ms"
log "  Exit: completed"
log "Done."
