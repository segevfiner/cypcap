import pytest


def pytest_addoption(parser, pluginmanager):
     parser.addoption("--interface", required=True, help="The interface to use for testing")


@pytest.fixture(scope='session')
def interface(pytestconfig):
    return pytestconfig.getoption('interface')
