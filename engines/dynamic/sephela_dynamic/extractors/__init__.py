"""Dynamic analysis extractors — registry of default extractors.

Each extractor is an independent module that parses one class of sandbox
artifact. Import them here so the pipeline can discover them.
"""

from __future__ import annotations

from sephela_dynamic.base import DynamicExtractor
from sephela_dynamic.extractors.frida import FridaExtractor
from sephela_dynamic.extractors.network import NetworkExtractor
from sephela_dynamic.extractors.logcat import LogcatExtractor


def default_extractors() -> list[DynamicExtractor]:
    """Return the default extractor chain in execution order."""
    return [
        FridaExtractor(),
        NetworkExtractor(),
        LogcatExtractor(),
    ]


__all__ = [
    "default_extractors",
    "FridaExtractor",
    "NetworkExtractor",
    "LogcatExtractor",
]
