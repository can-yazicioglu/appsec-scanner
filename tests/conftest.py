import pytest

from appsec.http import Budget, SafeSession
from appsec.scope import Scope
from tests.fixtures.lab import live_lab


@pytest.fixture
def lab():
    with live_lab() as result:
        yield result


@pytest.fixture
def client():
    session = SafeSession(Scope(["127.0.0.1"]), budget=Budget(1000, 120))
    yield session
    session.close()
