"""Errors shared by the coordinator and replay helpers."""


class OnlineLinkedError(ValueError):
    """A coordinator transition cannot be completed safely."""


class ReplayArtifactError(RuntimeError):
    """A replay artifact could not be loaded, correlated, or persisted."""

    def __init__(self, stage: str, detail: str) -> None:
        super().__init__(detail)
        self.stage = stage
