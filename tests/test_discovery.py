import copy
import tempfile
import unittest
from pathlib import Path

from workrelay.cli import database, discover, BridgeError
from workrelay.supervision import grant_enrollment, revoke_enrollment


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.config = {"authorized_owner": "alice"}
        self.sessions = {}
        self.calls = []
        self.db = database(self.root)
        self.addCleanup(self.db.close)

    def request(self, method, path):
        self.calls.append((method, path))
        self.assertEqual(method, "GET")
        self.assertTrue(path.startswith('/api/session/'))
        self.assertEqual(path.count('/'), 3, 'no global list, transcript or inference request')
        return {"data": copy.deepcopy(self.sessions.get(path.split('/')[-1]))}

    def task(self, key, owner='alice', workspace=None):
        sid = 'ses_bridge_' + format(len(self.sessions) + 1, '032x')
        workspace = workspace or str(self.root)
        self.sessions[sid] = {"id": sid, "projectID": "project", "location": {"directory": workspace},
                              "metadata": {"agentComputerBridge": key, "agentComputerBridgeOwner": owner}}
        self.db.execute('INSERT INTO tasks VALUES(?,?,?,?,?,?,?,?)',
                        (key, sid, 'msg_' + 'a' * 32, workspace, 'hash', 'running', owner, ''))
        return sid

    def enroll(self, owner='alice'):
        sid = 'ses_enrolled_' + str(len(self.sessions))
        self.sessions[sid] = {"id": sid, "projectID": "project", "location": {"directory": str(self.root)},
                              "metadata": {"unrelatedOwner": "preserved"}}
        return grant_enrollment(self.db, self, sid, owner, self.root,
                                local_admin_grant={"session_id": sid, "owner": owner, "workspace": str(self.root)})['grant_id']

    def test_scope_pagination_and_no_mutation(self):
        own = self.task('mine')
        hidden = self.task('hidden', 'bob')
        elsewhere = self.task('elsewhere', workspace='/other')
        grant = self.enroll()
        revoked = self.enroll()
        revoke_enrollment(self.db, revoked)
        self.enroll('bob')
        before = list(self.db.iterdump())
        self.calls.clear()
        page = discover(self.config, self, self.root, self.root, limit=1)
        items = page['items'][:]
        while page['next_offset'] is not None:
            page = discover(self.config, self, self.root, self.root, offset=page['next_offset'], limit=1)
            items.extend(page['items'])
        self.assertEqual({item['type'] for item in items}, {'run', 'enrolled_session'})
        self.assertEqual(len(items), 2)
        self.assertEqual(next(i for i in items if i['type'] == 'run')['key'], 'mine')
        enrolled = next(i for i in items if i['type'] == 'enrolled_session')
        self.assertEqual(enrolled['actions'], [{'tool': 'workrelay_enrolled_result', 'arguments': {'grant_id': grant}}])
        self.assertEqual(list(self.db.iterdump()), before)
        self.assertNotIn(('GET', '/api/session/' + hidden), self.calls)
        self.assertNotIn(('GET', '/api/session/' + elsewhere), self.calls)
        self.assertNotIn('_supervision_authority', self.config)
        self.sessions[own]['metadata'] = {}
        self.assertFalse(any(i['type'] == 'run' for i in discover(self.config, self, self.root, self.root)['items']))

    def test_empty_bounds_and_changed_enrollment(self):
        empty = discover(self.config, self, self.root, self.root)
        self.assertEqual(empty['items'], [])
        self.assertIn('enrollment', empty['empty_reason'])
        self.assertEqual(empty['projects'][0]['id'], 'configured-workspace')
        self.enroll()
        for session in self.sessions.values():
            session['metadata'] = {'changed': True}
        self.assertEqual(discover(self.config, self, self.root, self.root)['items'], [])
        for offset, limit in [(-1, 1), (0, 51), (0, 0), (True, 1)]:
            with self.assertRaises(BridgeError):
                discover(self.config, self, self.root, self.root, offset, limit)


if __name__ == '__main__':
    unittest.main()
