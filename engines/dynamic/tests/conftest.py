"""Shared test fixtures — golden sandbox artifacts for the dynamic engine.

Creates synthetic but realistic sandbox output files (Frida traces, network
logs, logcat) that exercise all extractors with edge cases including:
- Banking trojan compound patterns (SMS + crypto + reflection)
- Empty/minimal outputs
- Unicode and hostile content in log messages
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


@pytest.fixture()
def banking_trojan_artifacts(tmp_path: Path) -> Path:
    """Golden artifacts simulating a banking trojan (high-threat)."""

    # --- metadata.json ---
    _write_json(tmp_path / "metadata.json", {
        "sandbox_id": "sandbox-test-001",
        "emulator_image": "android-api-33-x86_64",
        "android_api_level": 33,
        "duration_ms": 120000,
        "apk_sha256": "a" * 64,
        "apk_package": "com.malicious.banking",
        "frida_version": "16.5.6",
        "network_isolated": True,
        "exit_reason": "completed",
    })

    # --- frida_trace.json ---
    _write_json(tmp_path / "frida_trace.json", {
        "version": "1.0",
        "apk_package": "com.malicious.banking",
        "total_hooks": 8,
        "entries": [
            {
                "timestamp_ms": 5000,
                "hook_type": "crypto",
                "class_name": "javax.crypto.Cipher",
                "method_name": "getInstance",
                "args": ["AES/CBC/PKCS5Padding"],
                "return_value": None,
                "stack_trace": ["com.malicious.banking.CryptoUtil.encrypt"],
                "metadata": {},
            },
            {
                "timestamp_ms": 5200,
                "hook_type": "crypto",
                "class_name": "javax.crypto.spec.SecretKeySpec",
                "method_name": "<init>",
                "args": ["key_len=16", "AES"],
                "return_value": None,
                "stack_trace": [],
                "metadata": {},
            },
            {
                "timestamp_ms": 8000,
                "hook_type": "reflection",
                "class_name": "java.lang.Class",
                "method_name": "forName",
                "args": ["com.hidden.PayloadLoader"],
                "return_value": None,
                "stack_trace": ["com.malicious.banking.Loader.init"],
                "metadata": {},
            },
            {
                "timestamp_ms": 8500,
                "hook_type": "dex_loading",
                "class_name": "dalvik.system.DexClassLoader",
                "method_name": "<init>",
                "args": ["/data/data/com.malicious.banking/files/payload.dex", "null"],
                "return_value": None,
                "stack_trace": ["com.malicious.banking.Loader.loadPayload"],
                "metadata": {},
            },
            {
                "timestamp_ms": 15000,
                "hook_type": "sms",
                "class_name": "android.telephony.SmsManager",
                "method_name": "sendTextMessage",
                "args": ["+1234567890", "body_redacted"],
                "return_value": None,
                "stack_trace": ["com.malicious.banking.SmsForwarder.send"],
                "metadata": {},
            },
            {
                "timestamp_ms": 20000,
                "hook_type": "network",
                "class_name": "java.net.URL",
                "method_name": "openConnection",
                "args": ["http://evil.example.com/gate"],
                "return_value": None,
                "stack_trace": [],
                "metadata": {},
            },
            {
                "timestamp_ms": 30000,
                "hook_type": "accessibility",
                "class_name": "android.accessibilityservice.AccessibilityService",
                "method_name": "onAccessibilityEvent",
                "args": ["TYPE_WINDOW_STATE_CHANGED"],
                "return_value": None,
                "stack_trace": [],
                "metadata": {},
            },
            {
                "timestamp_ms": 35000,
                "hook_type": "device_info",
                "class_name": "android.telephony.TelephonyManager",
                "method_name": "getDeviceId",
                "args": [],
                "return_value": "000000000000000",
                "stack_trace": [],
                "metadata": {},
            },
        ],
    })

    # --- network.json ---
    _write_json(tmp_path / "network.json", {
        "version": "1.0",
        "connections": [
            {
                "timestamp_ms": 10000,
                "protocol": "tcp",
                "src_ip": "10.0.2.15",
                "src_port": 45678,
                "dst_ip": "198.51.100.42",
                "dst_port": 443,
                "dst_hostname": "evil.example.com",
                "bytes_sent": 2048,
                "bytes_recv": 4096,
                "metadata": {},
            },
            {
                "timestamp_ms": 11000,
                "protocol": "tcp",
                "src_ip": "10.0.2.15",
                "src_port": 45680,
                "dst_ip": "203.0.113.10",
                "dst_port": 8080,
                "dst_hostname": None,
                "bytes_sent": 512,
                "bytes_recv": 1024,
                "metadata": {},
            },
            {
                "timestamp_ms": 12000,
                "protocol": "tcp",
                "src_ip": "10.0.2.15",
                "src_port": 45682,
                "dst_ip": "93.184.216.34",
                "dst_port": 4444,
                "dst_hostname": "c2.malware.net",
                "bytes_sent": 256,
                "bytes_recv": 512,
                "metadata": {},
            },
        ],
        "dns_queries": [
            {
                "timestamp_ms": 9000,
                "query": "evil.example.com",
                "query_type": "A",
                "response_ips": ["198.51.100.42"],
            },
            {
                "timestamp_ms": 9500,
                "query": "c2.malware.net",
                "query_type": "A",
                "response_ips": ["93.184.216.34"],
            },
        ],
        "http_requests": [
            {
                "timestamp_ms": 20000,
                "method": "POST",
                "url": "http://evil.example.com/gate",
                "host": "evil.example.com",
                "user_agent": "Dalvik/2.1.0",
                "content_type": "application/json",
                "status_code": 200,
                "is_cleartext": True,
            },
        ],
        "tls_handshakes": [
            {
                "timestamp_ms": 10500,
                "server_name": "evil.example.com",
                "ja3_hash": "abc123def456",
                "certificate_subject": "CN=evil.example.com",
                "certificate_issuer": "CN=evil.example.com",
                "certificate_serial": "1234567890",
            },
        ],
        "total_bytes_sent": 2816,
        "total_bytes_recv": 5632,
    })

    # --- logcat.json ---
    _write_json(tmp_path / "logcat.json", {
        "version": "1.0",
        "total_lines": 6,
        "entries": [
            {"timestamp_ms": 1000, "level": "I", "tag": "ActivityManager", "pid": 100,
             "message": "Starting com.malicious.banking/.MainActivity"},
            {"timestamp_ms": 5000, "level": "W", "tag": "CryptoUtil", "pid": 200,
             "message": "Cipher.init called with AES"},
            {"timestamp_ms": 8000, "level": "I", "tag": "SmsReceiver", "pid": 200,
             "message": "Received android.provider.Telephony.SMS_RECEIVED"},
            {"timestamp_ms": 15000, "level": "D", "tag": "WebView", "pid": 200,
             "message": "WebView.loadUrl(http://phish.example.com/overlay)"},
            {"timestamp_ms": 20000, "level": "I", "tag": "Loader", "pid": 200,
             "message": "DexClassLoader loading /data/payload.dex"},
            {"timestamp_ms": 30000, "level": "E", "tag": "AndroidRuntime", "pid": 200,
             "message": "FATAL EXCEPTION: Thread-42"},
        ],
    })

    return tmp_path


@pytest.fixture()
def clean_app_artifacts(tmp_path: Path) -> Path:
    """Golden artifacts simulating a benign app (no threats)."""

    _write_json(tmp_path / "metadata.json", {
        "sandbox_id": "sandbox-test-002",
        "emulator_image": "android-api-33-x86_64",
        "android_api_level": 33,
        "duration_ms": 60000,
        "apk_sha256": "b" * 64,
        "apk_package": "com.legit.calculator",
        "frida_version": "16.5.6",
        "network_isolated": True,
        "exit_reason": "completed",
    })

    _write_json(tmp_path / "frida_trace.json", {
        "version": "1.0",
        "apk_package": "com.legit.calculator",
        "total_hooks": 0,
        "entries": [],
    })

    _write_json(tmp_path / "network.json", {
        "version": "1.0",
        "connections": [],
        "dns_queries": [],
        "http_requests": [],
        "tls_handshakes": [],
        "total_bytes_sent": 0,
        "total_bytes_recv": 0,
    })

    _write_json(tmp_path / "logcat.json", {
        "version": "1.0",
        "total_lines": 2,
        "entries": [
            {"timestamp_ms": 1000, "level": "I", "tag": "ActivityManager", "pid": 100,
             "message": "Starting com.legit.calculator/.MainActivity"},
            {"timestamp_ms": 2000, "level": "I", "tag": "Calculator", "pid": 200,
             "message": "Calculator initialized"},
        ],
    })

    return tmp_path


@pytest.fixture()
def missing_artifacts(tmp_path: Path) -> Path:
    """Directory with only metadata — tests graceful degradation."""

    _write_json(tmp_path / "metadata.json", {
        "sandbox_id": "sandbox-test-003",
        "emulator_image": "android-api-33-x86_64",
        "android_api_level": 33,
        "duration_ms": 5000,
        "apk_sha256": "c" * 64,
        "apk_package": "com.test.missing",
        "frida_version": "16.5.6",
        "network_isolated": True,
        "exit_reason": "timeout",
    })

    return tmp_path
