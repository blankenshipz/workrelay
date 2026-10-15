import contextlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from workrelay import event_store as store


class EventStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / "private"
        self.state.mkdir(mode=0o700)
        self.args = {"op": "reserve", "principal": "alice", "name": "task.completed",
                     "arguments": {"task_id": "task1", "kind": "done"},
                     "url": "https://callback.example/events", "secret": "whsec_not-a-real-secret",
                     "ttl_ms": 60000}

    def test_canonical_restart_expiry_and_revoke(self):
        with store.connect(self.state) as db:
            first = store.execute(db, self.args, now=100000)
            self.assertFalse(first["verified"])
            self.assertEqual(store.execute(db, {"op": "due", "principal": "alice"}, now=100001), [])
            self.assertRaises(store.StoreError, store.execute, db, {"op": "queue", "principal": "alice",
                "id": first["id"], "event_id": "evt1", "payload": {}}, 100001)
        with store.connect(self.state) as db:
            changed = {**self.args, "arguments": {"kind": "done", "task_id": "task1"}}
            self.assertEqual(store.execute(db, changed, now=100100)["id"], first["id"])
            self.assertIsNone(store.execute(db, {"op": "get", "principal": "bob", "id": first["id"]}, now=100101))
            self.assertIsNotNone(store.execute(db, {"op": "get", "principal": "alice", "id": first["id"]}, now=100101))
            self.assertIsNone(store.execute(db, {"op": "get", "principal": "alice", "id": first["id"]}, now=170101))
            store.execute(db, {"op": "revoke", "principal": "bob", "id": first["id"]}, now=100102)
            self.assertIsNotNone(store.execute(db, {"op": "get", "principal": "alice", "id": first["id"]}, now=100103))
            store.execute(db, {"op": "revoke", "principal": "alice", "id": first["id"]}, now=100104)
            self.assertIsNone(store.execute(db, {"op": "get", "principal": "alice", "id": first["id"]}, now=100105))
        self.assertEqual((self.state / "events.sqlite").stat().st_mode & 0o777, 0o600)

    def test_private_directory_and_stdin_no_secret_output(self):
        self.state.chmod(0o755)
        with self.assertRaises(store.StoreError):
            store.connect(self.state)
        self.state.chmod(0o700)
        process = subprocess.run([sys.executable, '-m', 'workrelay.event_store', str(self.state)],
            input=json.dumps(self.args), capture_output=True, text=True,
            env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")})
        self.assertEqual(process.returncode, 0)
        self.assertNotIn(self.args["secret"], process.stdout + process.stderr)
        self.assertTrue(json.loads(process.stdout)["id"].startswith("sub_"))


if __name__ == "__main__":
    unittest.main()
