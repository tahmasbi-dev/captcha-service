from abc import ABC, abstractmethod

from captcha_service.domain.value_objects.redemption import RedemptionOutcome


class UsageMetrics(ABC):
    """Business-level counters the use cases emit as things happen.

    The infra implementation turns these into Prometheus counters; the
    use cases only know the port, never the exporter.
    """

    @abstractmethod
    def record_redeem(self, outcome: RedemptionOutcome) -> None:
        """A verify attempt resolved to this redemption outcome."""
        ...

    @abstractmethod
    def record_solve(self, solved: bool) -> None:
        """A submitted solution was judged right (solved) or wrong (burned)."""
        ...
