# Sephela Sandbox — Dynamic Analysis Environment

Isolated Android emulator environment for runtime malware analysis.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Docker Container (KVM passthrough, NET_ADMIN only)         │
│                                                             │
│  ┌─────────────────┐   ┌──────────────┐   ┌─────────────┐  │
│  │ Android Emulator │◄──│ Frida Server │   │   tcpdump   │  │
│  │   (API 33, x86)  │   │ (hooks .js)  │   │  (PCAP)     │  │
│  └────────┬─────────┘   └──────────────┘   └─────────────┘  │
│           │                                                  │
│  iptables: DEFAULT DENY egress (DNS to localhost only)       │
│                                                             │
│  Output → /output/{frida_trace,network,logcat,metadata}.json │
└─────────────────────────────────────────────────────────────┘
          ▼
  Python Engine (engines/dynamic/) parses artifacts → Evidence Envelope
```

## Security Controls

| Control | Implementation |
|---------|---------------|
| Network isolation | Docker `internal: true` network + iptables default-deny egress |
| Resource limits | 4 CPU, 8GB RAM limits in compose |
| Privilege minimization | Only `NET_ADMIN` + `/dev/kvm`, no `--privileged` |
| Filesystem isolation | `tmpfs` for emulator data, `-wipe-data` on boot |
| Ephemeral execution | Container is `--rm`, snapshot is read-only |
| No persistence | Emulator runs with `--no-snapshot-save` |

## Prerequisites

### WSL2 (Windows)

1. Enable nested virtualization in `.wslconfig`:
   ```ini
   [wsl2]
   nestedVirtualization=true
   memory=12GB
   processors=4
   ```

2. Restart WSL: `wsl --shutdown && wsl`

3. Verify KVM: `ls -la /dev/kvm`

4. Install Docker in WSL2

### Linux (bare metal / VM)

1. Verify KVM: `kvm-ok` or `ls /dev/kvm`
2. Install Docker

## Usage

```bash
# 1. Set up directories
mkdir -p __samples __output

# 2. Copy APK to analyse
cp /path/to/suspicious.apk __samples/target.apk

# 3. Run sandbox
docker compose -f docker-compose.sandbox.yml run --rm sandbox \
  /opt/sephela/run_analysis.sh /samples/target.apk /output

# 4. Artifacts are now in __output/
ls __output/
# frida_trace.json  network.json  logcat.json  metadata.json  raw/

# 5. Run the Python engine over the artifacts
cd ../../
python -c "
from sephela_dynamic import analyze
envelope = analyze('infra/sandbox/__output', job_id='test-001')
print(f'Status: {envelope.status.value}')
print(f'Findings: {len(envelope.findings)}')
"
```

## Files

| File | Purpose |
|------|---------|
| `Dockerfile.sandbox` | Multi-stage build: Android SDK + Frida + tools |
| `docker-compose.sandbox.yml` | Isolated container with KVM, resource limits |
| `run_analysis.sh` | Main orchestration: boot → install → hook → capture → collect |
| `frida_hooks.js` | Frida script hooking crypto, reflection, SMS, network APIs |
| `scripts/logcat_to_json.py` | Convert raw logcat to structured JSON |
| `scripts/frida_to_json.py` | Convert Frida JSON-lines to FridaTrace schema |
| `scripts/pcap_to_json.py` | Convert PCAP to NetworkTrace JSON |
