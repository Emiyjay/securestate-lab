import unittest

from securestate.ui.workers import BackgroundWorker


class TestBackgroundWorker(unittest.TestCase):
    def test_emits_result_for_successful_operation(self):
        received = []
        worker = BackgroundWorker("test-task", lambda: {"answer": 42})
        worker.signals.completed.connect(
            lambda *values: received.append(values)
        )

        worker.run()

        self.assertEqual(
            received,
            [("test-task", {"answer": 42}, None)],
        )

    def test_emits_error_for_failed_operation(self):
        received = []

        def fail():
            raise RuntimeError("network unavailable")

        worker = BackgroundWorker("test-task", fail)
        worker.signals.completed.connect(
            lambda *values: received.append(values)
        )

        worker.run()

        self.assertEqual(
            received,
            [("test-task", None, "network unavailable")],
        )


if __name__ == "__main__":
    unittest.main()
