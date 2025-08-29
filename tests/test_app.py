import os
import tempfile
import sys
from fastapi.testclient import TestClient
import pytest

sys.path.append(os.path.abspath('.'))

# ensure a temporary DB for tests
os.environ['DATABASE_URL'] = 'sqlite:///' + tempfile.mkstemp()[1]
os.environ['DISABLE_SCHEDULER'] = '1'

from backend.main import app, Base, engine  # noqa: E402

Base.metadata.create_all(bind=engine)


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


def test_redirect_to_login(client):
    resp = client.get('/')
    assert resp.status_code == 200
    # should render login because not authenticated
    assert 'Login' in resp.text


def test_login_and_dashboard(client):
    resp = client.post('/login', data={'username': 'admin', 'password': os.environ.get('ADMIN_PASSWORD', 'admin')})
    assert resp.status_code in (200, 302)
    resp = client.get('/')
    assert resp.status_code == 200
    assert 'Hosts' in resp.text
