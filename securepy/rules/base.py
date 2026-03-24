from __future__ import annotations

from abc import ABC, abstractmethod

from securepy.analysis.taint import ModuleAnalysis
from securepy.models.finding import Finding


class BaseRule(ABC):
    rule_id: str
    title: str

    @abstractmethod
    def run(self, analysis: ModuleAnalysis) -> list[Finding]:
        raise NotImplementedError