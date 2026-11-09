import os
import tempfile
import unittest
from unittest import mock

import db


class TempDatabaseTestCase(unittest.TestCase):
    """Runs every test against a fresh, empty SQLite file."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "test.db")
        patcher = mock.patch.object(db, "DB_NAME", self.db_path)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._tmp.cleanup)
        db.create_tables()
