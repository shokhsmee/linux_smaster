import pytest

from guardian.config import Config
from guardian.modules import Context
from guardian.store import Store


@pytest.fixture
def ctx(tmp_path):
    cfg = Config(state_dir=str(tmp_path / "state"))
    return Context(config=cfg, store=Store(tmp_path / "g.db"))
