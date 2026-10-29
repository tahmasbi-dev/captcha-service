from abc import ABC, abstractmethod

from captcha_service.domain.value_objects.redemption import RedemptionOutcome


class UsageMetrics(ABC):
    """Business counters that use cases bump as things happen.

    The infra side turns these into Prometheus counters. The use cases
    only ever see this port, never the exporter behind it.
    """

    @abstractmethod
    def record_redeem(self, outcome: RedemptionOutcome) -> None:
        """A verify attempt resolved to this redemption outcome."""
        ...

    @abstractmethod
    def record_solve(self, solved: bool) -> None:
        """A submitted solution was judged right or wrong (and spent)."""
        ...
