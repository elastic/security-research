import os
from typing import Dict, NoReturn, Union
from unittest import mock

import pytest

from elastic.cobalt_strike_extractor.config import GlobalConfig
from elastic.cobalt_strike_extractor.console import load_config

DEFAULT_CONFIG = {
    "input": {
        "elasticsearch": {
            "cloud": {},
            "hosts": [""],
            "ssl_verify": True,
            "index": "logs-endpoint.alerts-*",
            "enabled": True,
        }
    },
    "output": {
        "elasticsearch": {
            "cloud": {},
            "enabled": True,
            "hosts": [""],
            "index": "extraction-cobaltstrike",
            "ssl_verify": True,
        },
        "console": {"enabled": False, "pretty": False},
    },
}


def test_default_config():
    # These are the minimum required values that must be present in either the file or environment
    _cfg: GlobalConfig = GlobalConfig(**{})
    _cfg_dict = _cfg.get_dict()

    assert _cfg_dict == DEFAULT_CONFIG


ENV_CONFIG = {
    "input": {
        "elasticsearch": {
            "hosts": [""],
            "cloud": {},
            "ssl_verify": True,
            "index": "logs-endpoint.alerts-*",
            "enabled": False,
        }
    },
    "output": {
        "elasticsearch": {
            "enabled": False,
            "cloud": {},
            "hosts": [""],
            "index": "extraction-cobaltstrike",
            "ssl_verify": True,
        },
        "console": {"enabled": True, "pretty": False},
    },
}


def test_env_config():
    with mock.patch.dict(
        os.environ,
        {
            "INPUT_ELASTICSEARCH_ENABLED": "False",
            "OUTPUT_ELASTICSEARCH_ENABLED": "False",
            "OUTPUT_CONSOLE_ENABLED": "True",
        },
    ):
        _cfg: GlobalConfig = GlobalConfig({})
        _cfg_dict = _cfg.get_dict()

        assert _cfg_dict == ENV_CONFIG


@pytest.fixture
def sample_config(shared_datadir) -> Union[Dict[str, Dict[str, str]], NoReturn]:
    assert (shared_datadir / "sample_config.yml").exists()

    _cfg = load_config((shared_datadir / "sample_config.yml"))
    return _cfg


FILE_CONFIG = {
    "input": {
        "elasticsearch": {
            "cloud": {},
            "hosts": ["http://1.2.3.4:9200"],
            "ssl_verify": True,
            "index": "logs-endpoint.alerts-*",
            "enabled": True,
        }
    },
    "output": {
        "elasticsearch": {
            "cloud": {},
            "enabled": True,
            "hosts": ["http://1.2.3.4:9200"],
            "index": "extraction-cobaltstrike",
            "ssl_verify": True,
        },
        "console": {"enabled": False, "pretty": False},
    },
}


def test_file_config(sample_config):

    _cfg: GlobalConfig = GlobalConfig(**sample_config)
    _cfg_dict = _cfg.get_dict()

    assert _cfg_dict == FILE_CONFIG
