from PySide6.QtCore import QObject, QRunnable, Signal


class WorkerSignals(QObject):
    completed = Signal(str, object, object)


class BackgroundWorker(QRunnable):
    """Run a callable outside the GUI thread and report its outcome."""

    def __init__(self, task_key, function):
        super().__init__()
        self.task_key = task_key
        self.function = function
        self.signals = WorkerSignals()

    def run(self):
        try:
            result = self.function()
        except Exception as error:
            self.signals.completed.emit(
                self.task_key, None, str(error)
            )
        else:
            self.signals.completed.emit(
                self.task_key, result, None
            )
