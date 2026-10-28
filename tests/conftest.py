import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app.core.database import PasswordDatabase  # noqa: E402

QUESTIONS = [{"question_text": f"Q{i}", "answer": f"Answer {i}"} for i in range(3)]


@pytest.fixture
def db(tmp_path):
    return PasswordDatabase(str(tmp_path / "vault.db"))
