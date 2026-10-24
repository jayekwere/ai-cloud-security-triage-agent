import json

import pytest

from cloudtriage.models import normalize
from cloudtriage.pipeline import data_path
from cloudtriage.policy import Policy


@pytest.fixture
def findings():
    return normalize(json.loads(data_path("findings.json").read_text()))[0]


@pytest.fixture
def policy():
    return Policy(data_path("policy.toml"))
