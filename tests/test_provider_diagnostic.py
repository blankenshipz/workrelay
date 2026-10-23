import json
import sqlite3
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from workrelay.attestor import payload, AttestationError, provider_evidence
from workrelay.cli import InstalledClient, BridgeError, GuardFailure
from workrelay.managed_control import initialize, record_denial
from workrelay.provider_diagnostic import attach, sanitize


class ProviderDiagnosticTests(unittest.TestCase):
    def test_shapes_errors_and_hostile_values_preserve_checks(self):
        class Client:
            _provider_http_status = None
            def request(self, *args):
                return self.response
        c = Client()
        for value, envelope, data in [(None, 'null', 'unknown'), ({}, 'object', 'unknown'),
                ({'data': None}, 'object', 'null'), ({'data': 'PRIVATE_CANARY'}, 'object', 'string')]:
            c.response = value
            with self.assertRaises(AttestationError) as caught:
                payload(c, '/api/provider/openai')
            self.assertEqual(caught.exception.check_id, 'PROVIDER_RESPONSE')
            d = caught.exception.provider_diagnostic
            self.assertEqual((d['envelope_shape'], d['data_shape']), (envelope, data))
            self.assertNotIn('PRIVATE_CANARY', json.dumps(d))
        for value in [{'data': []}, {'data': {'id': 'openai'}}]:
            c.response = value
            self.assertIs(payload(c, '/api/provider/openai'), value['data'])
        for error in [BridgeError('PRIVATE_CANARY'), TimeoutError('PRIVATE_CANARY')]:
            with patch.object(c, 'request', side_effect=error):
                with self.assertRaises(AttestationError) as caught:
                    payload(c, '/api/provider/openai')
                self.assertEqual(caught.exception.check_id, 'PROVIDER_READ_UNAVAILABLE')
                self.assertEqual(caught.exception.provider_diagnostic['stage'], 'read')
        class Hostile(dict):
            def get(self, *args):
                raise AssertionError('extra getter')
        e = AttestationError(check_id='PROVIDER_RESPONSE')
        attach(e, c, 'envelope', Hostile(data='PRIVATE_CANARY'))
        self.assertNotIn('PRIVATE_CANARY', json.dumps(e.provider_diagnostic))
        self.assertIsNone(sanitize(Hostile(stage='read')))
        with patch('workrelay.provider_diagnostic.attach', side_effect=RuntimeError('PRIVATE_CANARY')):
            provider_evidence(e, c, 'read')  # optional diagnostic cannot throw

    def test_transport_status_provenance_reset_and_timeout_parity(self):
        c = InstalledClient({'node_executable': 'node', '_private_path': 'fixture'})
        def result(data, status=200, native=None, code=0):
            return SimpleNamespace(returncode=code, stdout=json.dumps({'status': status, 'data': data,
                'provider_diagnostic': {'http_status': native}}))
        for wrapper, expected, native in [(result(None,404,404), None,404),
                (result(None,404,200),None,200), (result({'data': {}},native=200),{'data': {}},200),
                (result(None,404),None,None)]:
            with patch('workrelay.cli.subprocess.run', return_value=wrapper):
                self.assertEqual(c.request('GET','/api/provider/openai'),expected)
                self.assertEqual(c._provider_http_status,native)
        for error in [subprocess.TimeoutExpired('fixture',20),OSError('PRIVATE_CANARY')]:
            with patch('workrelay.cli.subprocess.run', side_effect=error):
                with self.assertRaises(BridgeError):c.request('GET','/api/provider/openai')
                self.assertIsNone(c._provider_http_status)
        with patch('workrelay.cli.subprocess.run', return_value=result(None,native=403,code=2)):
            with self.assertRaises(BridgeError):c.request('GET','/api/provider/openai')
            self.assertEqual(c._provider_http_status,403)

    def test_durable_denial_no_backfill_and_finite_projection(self):
        db=sqlite3.connect(':memory:',isolation_level=None)
        self.addCleanup(db.close);initialize(db)
        db.execute("INSERT INTO managed_operations(binding,session,operation,kind,digest,message,phase,identity) VALUES('b','s','o','queue','d','m','reserved','{}')")
        e=GuardFailure('ATTESTATION_FAILED',attestation_check_id='PROVIDER_RESPONSE')
        e.provider_diagnostic={'stage':'envelope','http_status':404,'envelope_shape':'null','data_shape':'unknown','body':'PRIVATE_CANARY'}
        record_denial(db,'b','s','o',e)
        before=db.execute('SELECT * FROM managed_operations').fetchall()
        e.provider_diagnostic['http_status']=200
        record_denial(db,'b','s','o',e)
        self.assertEqual(before,db.execute('SELECT * FROM managed_operations').fetchall())
        stored=db.execute('SELECT provider_diagnostic FROM managed_operations').fetchone()[0]
        self.assertEqual(json.loads(stored)['http_status'],404)
        self.assertNotIn('PRIVATE_CANARY',stored)
