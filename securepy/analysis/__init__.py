from __future__ import annotations

from typing import TYPE_CHECKING

__all__ = ["ModuleAnalyzer", "ModuleAnalysis", "SummaryBuilder"]

if TYPE_CHECKING:
	from securepy.analysis.interprocedural import SummaryBuilder
	from securepy.analysis.taint import ModuleAnalysis, ModuleAnalyzer


def __getattr__(name: str):
	if name in {"ModuleAnalyzer", "ModuleAnalysis"}:
		from securepy.analysis.taint import ModuleAnalysis, ModuleAnalyzer

		return {
			"ModuleAnalyzer": ModuleAnalyzer,
			"ModuleAnalysis": ModuleAnalysis,
		}[name]

	if name == "SummaryBuilder":
		from securepy.analysis.interprocedural import SummaryBuilder

		return SummaryBuilder

	raise AttributeError(f"module 'securepy.analysis' has no attribute {name!r}")