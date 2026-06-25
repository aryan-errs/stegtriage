import pytest


@pytest.fixture(scope="session", autouse=True)
def generate_fixtures():
    """Generate all test fixtures once per session if they are absent."""
    from tests.make_fixtures import FIXTURES_DIR, make_all
    if not any(FIXTURES_DIR.glob("*.*")):
        make_all()
