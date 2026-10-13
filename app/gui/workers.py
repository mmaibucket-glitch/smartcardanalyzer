"""Reusable QThread worker for long-running card operations."""

from __future__ import annotations

from typing import Callable

from PySide6.QtCore import QThread, Signal


class Runner(QThread):
    """Runs a callable on a background thread.

    The callable receives ``emit`` (publish a step event to the GUI) and
    ``should_stop`` (True once stop() was called) and returns a result that
    is delivered via ``completed``.
    """

    step = Signal(object)
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, fn: Callable, parent=None) -> None:
        super().__init__(parent)
        self._fn = fn
        self._stop = False

    def run(self) -> None:
        try:
            result = self._fn(self.step.emit, lambda: self._stop)
        except Exception as exc:
            self.failed.emit(str(exc))
            return
        self.completed.emit(result)

    def stop(self) -> None:
        self._stop = True
