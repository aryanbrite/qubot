import pytest


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    """Every test gets its own key directory; nothing touches the real ~/.pqsecure."""
    monkeypatch.setenv("PQSECURE_HOME", str(tmp_path / "pq"))
