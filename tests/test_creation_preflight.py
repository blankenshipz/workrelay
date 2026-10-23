"""Creation policy regression: stop before sending; never create a native session.

Managed creation is non-inferencing and has no attestation call. Continuation
admission subsequently binds to the created native session, not a create flag.
"""
import copy
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from workrelay.cli import BridgeError
from workrelay.managed_control import create_session, creation_session_id


class BeforeSend(Exception):
    pass


class PreflightLedger:
    def __init__(self, db):
        self.db = db
        self.ready = False

    def __getattr__(self, name):
        return getattr(self.db, name)

    def execute(self, sql, *args):
        if sql.startswith("UPDATE managed_operations SET phase='sending'"):
            self.ready = True
            raise BeforeSend('fixture stops before transition or native POST')
        return self.db.execute(sql, *args)


class CreationPreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = str(Path(self.tmp.name).resolve())
        self.config = {'directory': self.root, 'model': {'providerID': 'openai', 'id': 'fixture'}, 'agent': 'quick-builder'}
        self.binding = 'a' * 64
        self.projects = [{'id': 'selected', 'canonical': self.root}]
        self.requests = []
        self.session = None
        db = sqlite3.connect(':memory:', isolation_level=None)
        self.addCleanup(db.close)
        self.db = PreflightLedger(db)

    def authorize(self):
        if self.binding is None:
            raise BridgeError('revoked fixture')
        return self.binding

    def request(self, method, path, body=None):
        self.requests.append((method, path))
        self.assertEqual(method, 'GET', 'no native POST may be reached')
        if path == '/api/project':
            return copy.deepcopy(self.projects)
        self.assertTrue(path.startswith('/api/session/'))
        return self.session

    def create(self, **kwargs):
        return create_session(self.db, self.config, self, self.authorize, 'preflight',
            title='Fixture', project_id='selected', authorize_native_projects=self.authorize, **kwargs)

    def test_existing_creation_policy_reaches_presend_without_admission(self):
        # A discovered canonical native root is already authorized by the pinned
        # server-wide principal. It need not be the private default workspace.
        target = Path(self.root) / 'native project &%'
        target.mkdir()
        self.projects = [{'id': 'selected', 'canonical': str(target)}]
        with patch('workrelay.managed_control.admission', side_effect=AssertionError('not a create stage')) as admission:
            with self.assertRaises(BeforeSend):
                self.create()
            admission.assert_not_called()
        self.assertTrue(self.db.ready)
        row = self.db.execute('SELECT phase,identity FROM managed_operations').fetchone()
        import json
        body = json.loads(row[1])
        self.assertEqual(row[0], 'reserved')
        self.assertEqual(body['location'], {'directory': str(target)})
        self.assertEqual(body['id'], creation_session_id(self.binding, 'preflight'))
        self.assertNotIn('permissions', body)
        self.assertNotIn('parentID', body)
        self.assertTrue(all(method == 'GET' for method, _ in self.requests))
        self.assertNotIn(('GET', '/api/plugin'), self.requests)

    def test_absent_ambiguous_project_and_untrusted_directory_refuse(self):
        for projects, directory in [([], None),
                ([{'id': 'selected', 'canonical': self.root}] * 2, None),
                (self.projects, '/not-a-real-creation-target'),
                ([{'id': 'selected', 'canonical': '/'}], None)]:
            with self.subTest(projects=projects, directory=directory):
                self.projects = projects
                with self.assertRaises(BridgeError):
                    self.create(directory=directory)
                self.assertFalse(self.db.ready)
                # Identical retries remain read-only denied receipts, not a new
                # attempt with repaired arguments or another location.
                before = len(self.requests)
                result = self.create(directory=directory)
                self.assertEqual(result['phase'], 'denied')
                self.assertEqual(len(self.requests), before)
                self.db.execute('DELETE FROM managed_operations')

    def test_revocation_and_preexisting_session_refuse(self):
        self.binding = None
        with self.assertRaises(BridgeError):
            self.create()
        self.assertEqual(self.requests, [])
        self.binding = 'a' * 64
        self.session = {'data': {'id': creation_session_id(self.binding, 'preflight')}}
        with self.assertRaises(BridgeError):
            self.create()
        self.assertFalse(self.db.ready)

    def test_profile_authority_does_not_infer_an_unlisted_native_root(self):
        other = Path(self.root) / 'other'
        other.mkdir()
        self.projects = [{'id': 'selected', 'canonical': str(other)}]
        with self.assertRaises(BridgeError):
            create_session(self.db, self.config, self, self.authorize, 'profile',
                title='Fixture', project_id='selected', directory=str(other))
        self.assertFalse(self.db.ready)
