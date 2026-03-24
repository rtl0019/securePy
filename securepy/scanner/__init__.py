from __future__ import annotations

from typing import TYPE_CHECKING

__all__ = ["ScanConfig", "SecurePyOrchestrator"]

if TYPE_CHECKING:
	from securepy.scanner.orchestrator import ScanConfig, SecurePyOrchestrator


def __getattr__(name: str):
	if name in __all__:
		from securepy.scanner.orchestrator import ScanConfig, SecurePyOrchestrator

		return {
			"ScanConfig": ScanConfig,
			"SecurePyOrchestrator": SecurePyOrchestrator,
		}[name]
	raise AttributeError(f"module 'securepy.scanner' has no attribute {name!r}")