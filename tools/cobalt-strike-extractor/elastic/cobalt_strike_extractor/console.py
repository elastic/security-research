#!/usr/bin/env python3
# code: language=python spaces=4 insertspaces
"""
Usage:  cobalt-strike-extractor [-v | -vv | -vvv | -q | --debug] [--since DATEMATH] [-c FILE] [-d DIR]
        cobalt-strike-extractor --version

Options:
    -h --help                   show this help message and exit
    --version                   show version and exit
    -c FILE --config=FILE       path to YAML configuration [default: config.yml]
    --since DATE                ISO date time string or Elastic datemath for earliest event
    -v                          increase verbosity (can be used up to 3 times)
    -q                          quiet mode
    --debug                     enable debug logging for all Python modules
"""

import logging
import os
from importlib.metadata import version
from typing import Dict, NoReturn, Union

from docopt import docopt
from ruamel.yaml import YAML
from scalpl import Cut

from . import LOGGER_NAME, __version__
from .extractor import CSBeaconExtractor

logger = logging.getLogger(LOGGER_NAME)


def setup_logger(args: Dict[str, str]) -> None:
    _verbosity: int = 0
    _loggername = LOGGER_NAME
    if not args["-q"] is True:
        _verbosity = 30 + (int(args["-v"]) * -10)
        # If this is set to 0, it defaults to the root logger configuration,
        # which we don't want to manipulate because it will spam from other modules
        if _verbosity == 0:
            _verbosity = 5
    else:
        _verbosity = 40
        _cscelog = logging.getLogger("libcsce.parser")
        _cscelog.setLevel(_verbosity)
    if args["--debug"] is True:
        # Enable full logging for all loggers
        _loggername = None
        _verbosity = 10

    logger = logging.getLogger(name=__name__)

    if _verbosity < 20:
        FORMAT = "[%(asctime)s.%(msecs)03d][%(filename)20s:%(lineno)-4s][%(threadName)s][ %(funcName)20s() ][%(levelname)s] %(message)s"
    else:
        FORMAT = "[%(asctime)s.%(msecs)03d][%(levelname)s] %(message)s"

    logger = logging.getLogger(_loggername)
    logging.basicConfig(format=FORMAT, datefmt="%Y-%m-%dT%H:%M:%S")
    logger.setLevel(_verbosity)


def load_config(filename: str) -> Union[Dict[str, Dict[str, str]], NoReturn]:
    logger.debug(f"load_config: {filename}")
    _yaml = YAML()
    _cfg = {}
    if os.path.exists(filename):
        with open(filename) as f:
            _f = _yaml.load(f)
            _cfg = Cut({})
            for k, v in _f.items():
                if isinstance(v, dict):
                    _cfg2 = Cut({})
                    for kk, vv in v.items():
                        _cfg2.setdefault(kk, vv)
                    v = dict(_cfg2)

                _cfg.setdefault(k, v)

            return dict(_cfg)
    else:
        return {}


def main() -> None:
    elasticsearch_ver = version("elasticsearch")
    my_version: str = (
        f"{__name__}  v{__version__}\n"
        f"elasticsearch                          v{ elasticsearch_ver }\n"
    )
    arguments: Dict[str, str] = docopt(__doc__, version=my_version)
    setup_logger(arguments)
    logger.debug("logger setup complete")

    _cfg: dict[str, dict] = {}
    if "--config" in arguments and os.path.exists(arguments["--config"]):
        _cfg = load_config(arguments["--config"])

    _extractor = CSBeaconExtractor(_cfg)
    _extractor.run()
