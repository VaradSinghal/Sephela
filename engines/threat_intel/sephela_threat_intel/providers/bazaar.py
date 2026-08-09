"""MalwareBazaar (abuse.ch) — sample-level intel keyed by file hash.

The single most valuable provider for this platform's core question: *is this
exact APK already a known fraudulent banking app?* Bazaar answers with a curated
family ``signature`` (e.g. ``Cerberus``, ``Anatsa``, ``Hydra``) plus community
tags, which flow straight into the scoring engine's family-attribution weighting
and give the report a name an analyst can act on.

A hit here is unambiguous — Bazaar only indexes confirmed malware — so the
verdict is malicious with maximum confidence and no thresholding.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sephela_threat_intel.base import Provider, ProviderResult, Verdict
from sephela_threat_intel.iocs import Ioc, IocType
from sephela_threat_intel.providers.http import request_json, str_list

if TYPE_CHECKING:  # pragma: no cover
    import httpx

API_URL = "https://mb-api.abuse.ch/api/v1/"


class MalwareBazaarProvider(Provider):
    name = "bazaar"
    supports = frozenset({IocType.hash})
    requests_per_minute = 60

    @property
    def configured(self) -> bool:
        # Historically keyless; newer deployments require an Auth-Key. Either
        # way the provider is usable, so it is never skipped for lack of a key.
        return True

    async def lookup(self, ioc: Ioc, client: httpx.AsyncClient) -> ProviderResult:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Auth-Key"] = self.api_key

        payload = await request_json(
            client,
            "POST",
            API_URL,
            provider=self.name,
            headers=headers,
            data={"query": "get_info", "hash": ioc.value},
        )
        # Bazaar reports "hash_not_found" in the body with HTTP 200.
        if payload is None or payload.get("query_status") != "ok":
            return ProviderResult(
                ioc=ioc,
                provider=self.name,
                verdict=Verdict.unknown,
                summary="Sample not present in MalwareBazaar",
                raw={"found": False, "query_status": _status(payload)},
            )

        entries = payload.get("data")
        entry = entries[0] if isinstance(entries, list) and entries else {}
        if not isinstance(entry, dict):
            entry = {}

        signature = entry.get("signature")
        family = signature.strip() if isinstance(signature, str) and signature.strip() else None
        tags = str_list(entry.get("tags"), limit=15)

        return ProviderResult(
            ioc=ioc,
            provider=self.name,
            verdict=Verdict.malicious,
            score=1.0,
            families=[family] if family else [],
            signatures=_vendor_signatures(entry) or tags,
            summary=(
                f"Known malware sample in MalwareBazaar"
                f"{f' — family {family}' if family else ''}"
            ),
            raw={
                "found": True,
                "signature": family,
                "file_type": entry.get("file_type")
                if isinstance(entry.get("file_type"), str)
                else None,
                "first_seen": entry.get("first_seen")
                if isinstance(entry.get("first_seen"), str)
                else None,
                "reporter": entry.get("reporter")
                if isinstance(entry.get("reporter"), str)
                else None,
                "tags": tags,
                "delivery_method": entry.get("delivery_method")
                if isinstance(entry.get("delivery_method"), str)
                else None,
            },
        )


def _vendor_signatures(entry: dict[str, Any]) -> list[str]:
    """Pull detection names out of Bazaar's ``vendor_intel`` block.

    The block's shape varies per vendor (some nest a list of scans, some a single
    object), so every branch is defensive — this is untrusted third-party JSON.
    """
    vendor_intel = entry.get("vendor_intel")
    if not isinstance(vendor_intel, dict):
        return []

    names: list[str] = []
    for vendor, detail in vendor_intel.items():
        candidates: list[Any] = detail if isinstance(detail, list) else [detail]
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            for key in ("detection", "malware_family", "verdict", "signature", "family_name"):
                value = candidate.get(key)
                if isinstance(value, str) and value.strip():
                    label = f"{vendor}: {value.strip()}"[:128]
                    if label not in names:
                        names.append(label)
                    break
        if len(names) >= 15:
            break
    return names


def _status(payload: dict[str, Any] | None) -> str:
    if payload is None:
        return "http_404"
    status = payload.get("query_status")
    return status if isinstance(status, str) else "unknown"
