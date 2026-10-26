"""Explicit policy selection and supervised memory failure, with no real inputs."""
import psutil
import sys
import unittest
from unittest.mock import patch

from leakguard_core._supervision import WorkerError, run_worker, worker_capabilities
from leakguard_core.api import ConfigurationError, ScanConfig


class WorkerPolicyTests(unittest.TestCase):
    def test_strict_mac_policy_rejects_before_launch(self):
        with patch('leakguard_core._supervision.sys.platform', 'darwin'), patch('leakguard_core._supervision.subprocess.Popen') as start:
            with self.assertRaises(WorkerError) as failure:
                run_worker([sys.executable, '-I', '-c', 'pass'], b'', timeout=2)
            self.assertEqual(failure.exception.code, 'resource-bound-unavailable')
            start.assert_not_called()

    def test_supervised_policy_runs_on_mac_without_hard_allocation_claim(self):
        with patch('leakguard_core._supervision.sys.platform', 'darwin'):
            output = run_worker([sys.executable, '-I', '-c', 'import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())'], b'synthetic', timeout=3, worker_policy='supervised-alpha')
            self.assertEqual(output.stdout, b'synthetic')
            capability = worker_capabilities('supervised-alpha')
            self.assertTrue(capability['available'])
            self.assertFalse(capability['hard_memory_cap'])
            self.assertEqual(capability['memory_enforcement'], 'rss-watchdog')

    def test_watchdog_aborts_memory_overshoot(self):
        with patch('leakguard_core._supervision.sys.platform', 'darwin'):
            with self.assertRaises(WorkerError) as failure:
                run_worker([sys.executable, '-I', '-c', 'import time;x=bytearray(16000000);time.sleep(2)'], b'', timeout=3, memory_bytes=1_000_000, worker_policy='supervised-alpha')
            self.assertEqual(failure.exception.code, 'worker-memory-limit')

    def test_policy_and_concurrency_are_validated_and_copied(self):
        config = ScanConfig.from_mapping({'worker_policy': 'supervised-alpha', 'scan_workers': 1})
        self.assertEqual(config.to_mapping()['worker_policy'], 'supervised-alpha')
        for invalid in ({'worker_policy': []}, {'worker_policy': 'fallback'}, {'scan_workers': True}, {'scan_workers': 3}, {'extension_registry': 'relative'}):
            with self.subTest(invalid=invalid), self.assertRaises(ConfigurationError):
                ScanConfig.from_mapping(invalid)
