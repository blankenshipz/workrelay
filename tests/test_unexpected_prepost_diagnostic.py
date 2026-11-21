"""r28: UNEXPECTED_PREPOST records a finite, secret-free exception class/site."""
import json
import sqlite3
import subprocess
import unittest
from unittest.mock import patch

from workrelay.cli import BridgeError, GuardFailure, InstalledClient, TransportFailure
from workrelay.guard_diagnostic import sanitize_unexpected, unexpected_evidence
from workrelay.managed_control import initialize, record_denial


def completed(stdout, returncode=0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr='PRIVATE stderr')


class TransportReasonTests(unittest.TestCase):
    client = InstalledClient({'node_executable': '/fixture/node', '_private_path': '/fixture/config.json'})

    def reason(self, **kwargs):
        with patch('workrelay.cli.subprocess.run', **kwargs):
            with self.assertRaises(TransportFailure) as raised:
                self.client.request('GET', '/api/agent/harness-router?location%5Bdirectory%5D=%2Fx')
        self.assertIsInstance(raised.exception, BridgeError)
        return raised.exception.transport_reason

    def test_truncated_stdout_is_named(self):
        # The live failure: transport exit 0 with stdout cut at 65536 bytes.
        truncated = json.dumps({'status': 200, 'data': {'permission': ['x' * 100] * 2000}})[:65536]
        self.assertEqual(self.reason(return_value=completed(truncated)), 'transport_output_not_json')

    def test_each_transport_failure_reason(self):
        self.assertEqual(self.reason(return_value=completed('', 2)), 'transport_exit')
        self.assertEqual(self.reason(side_effect=subprocess.TimeoutExpired('node', 20)), 'transport_timeout')
        self.assertEqual(self.reason(side_effect=FileNotFoundError('PRIVATE')), 'transport_os_error')
        self.assertEqual(self.reason(return_value=completed('[]')), 'transport_response_malformed')
        self.assertEqual(self.reason(return_value=completed('{"status": 200}')), 'transport_response_malformed')
        self.assertEqual(self.reason(return_value=completed('{"status": 500, "data": null}')), 'native_http_status')
        with patch('workrelay.cli.subprocess.run', return_value=completed('{"status": 404, "data": null}')):
            self.assertIsNone(self.client.request('GET', '/api/session/ses_x'))
        with patch('workrelay.cli.subprocess.run', return_value=completed('{"status": 200, "data": {"ok": 1}}')):
            self.assertEqual(self.client.request('GET', '/api/session/ses_x'), {'ok': 1})


class UnexpectedPrepostLedgerTests(unittest.TestCase):
    def ledger(self):
        db = sqlite3.connect(':memory:', isolation_level=None)
        self.addCleanup(db.close)
        initialize(db)
        for op in ('one', 'two', 'three'):
            db.execute("INSERT INTO managed_operations(binding,session,operation,kind,digest,message,phase,identity) "
                       "VALUES('binding','ses_fixture',?,'create','digest','project','reserved','{}')", (op,))
        return db

    def raised(self, factory):
        try:
            factory()
        except Exception as error:  # noqa: BLE001 - capture the real traceback
            return error
        raise AssertionError('expected failure')

    def test_records_class_transport_and_site_never_text(self):
        db = self.ledger()
        client = InstalledClient({'node_executable': '/fixture/node', '_private_path': '/fixture/config.json'})
        with patch('workrelay.cli.subprocess.run', return_value=completed('{"status":200,"data":{"PRIVATE-SECRET')):
            error = self.raised(lambda: client.request('GET', '/api/agent/harness-router'))
        record_denial(db, 'binding', 'ses_fixture', 'one', error)
        code, raw = db.execute("SELECT denial_code,guard_diagnostic FROM managed_operations WHERE operation='one'").fetchone()
        self.assertEqual(code, 'UNEXPECTED_PREPOST')
        diagnostic = json.loads(raw)
        self.assertEqual(diagnostic['exception'], 'TransportFailure')
        self.assertEqual(diagnostic['transport'], 'transport_output_not_json')
        self.assertEqual(diagnostic['frames'][-1]['module'], 'cli')
        self.assertEqual(diagnostic['frames'][-1]['function'], 'request')
        self.assertNotIn('PRIVATE', raw); self.assertNotIn('/fixture', raw); self.assertNotIn('harness-router', raw)

    def test_plain_exception_class_and_unknown_class(self):
        db = self.ledger()
        record_denial(db, 'binding', 'ses_fixture', 'two', self.raised(lambda: {}['PRIVATE-KEY']))
        diagnostic = json.loads(db.execute("SELECT guard_diagnostic FROM managed_operations WHERE operation='two'").fetchone()[0])
        self.assertEqual((diagnostic['exception'], diagnostic['transport']), ('KeyError', None))
        class PrivateCustomError(Exception):
            pass
        self.assertEqual(unexpected_evidence(PrivateCustomError('PRIVATE'))['exception'], 'other')

    def test_guard_denials_unchanged_and_no_backfill(self):
        db = self.ledger()
        record_denial(db, 'binding', 'ses_fixture', 'three', GuardFailure('CREATE_PROJECT_WORKSPACE_MISMATCH'))
        self.assertEqual(db.execute("SELECT denial_code,guard_diagnostic FROM managed_operations WHERE operation='three'").fetchone(),
                         ('CREATE_PROJECT_WORKSPACE_MISMATCH', None))
        record_denial(db, 'binding', 'ses_fixture', 'three', ValueError('later'))
        self.assertIsNone(db.execute("SELECT guard_diagnostic FROM managed_operations WHERE operation='three'").fetchone()[0])

    def test_sanitizer_rejects_foreign_shapes(self):
        self.assertIsNone(sanitize_unexpected({'reason': 'other'}))
        safe = sanitize_unexpected({'reason': 'unexpected_prepost', 'exception': 'PRIVATE', 'transport': 'PRIVATE',
            'frames': [{'module': 'evil', 'function': 'f', 'line': 1}, {'module': 'cli', 'function': 'PRIVATE TEXT', 'line': 1},
                       {'module': 'cli', 'function': 'request', 'line': -1}, {'module': 'cli', 'function': 'request', 'line': 9}, 'x']})
        self.assertEqual(safe, {'version': 1, 'reason': 'unexpected_prepost', 'exception': 'other', 'transport': None,
                                'frames': [{'module': 'cli', 'function': 'request', 'line': 9}]})


if __name__ == '__main__':
    unittest.main()
