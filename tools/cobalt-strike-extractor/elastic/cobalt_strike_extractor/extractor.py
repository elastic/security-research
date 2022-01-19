#!/usr/bin/env python3
import base64
import json
import logging
import os
import sys
import zlib
from itertools import tee
from typing import Any, Iterable, cast

from elasticsearch import Elasticsearch, helpers
from libcsce import error
from libcsce.parser import CobaltStrikeConfigParser
from scalpl import Cut

from . import LOGGER_NAME
from .config import GlobalConfig, _drop_nones

logger = logging.getLogger(LOGGER_NAME)


def _connect_es(es_config: dict[str, str] = {}):
    _es: Elasticsearch = None
    _apikey: tuple(str) = None
    _httpauth: tuple(str) = None

    es_config = Cut(es_config)

    if es_config.get("enabled", False):
        if es_config.get("cloud.auth", None):
            _httpauth = tuple(es_config.get("cloud.auth").split(":"))
        elif es_config.get("username", None) and es_config.get("password", None):
            _httpauth = (
                es_config.get("username"),
                es_config.get("password"),
            )

        if es_config.get("api_key", None):
            _apikey = tuple(es_config.get("api_key").split(":"))

        if _httpauth is not None and _apikey is not None:
            logger.critical(
                "Either username/password auth or api_key auth should be used for elasticsearch, not both."
            )
            sys.exit(1)

        if es_config.get("cloud.id", None):
            logger.debug(
                f"Connecting to Elasticsearch using cloud.id {es_config.get('cloud.id')}"
            )
            _es = Elasticsearch(
                cloud_id=es_config.get("cloud.id"),
                verify_certs=es_config.get("ssl_verify", True),
                http_auth=_httpauth,
                api_key=_apikey,
                timeout=30,
                max_retries=10,
                retry_on_timeout=True,
            )
        else:
            logger.debug(
                f"Connecting to Elasticsearch using hosts: {es_config.get('hosts', ['127.0.0.1:9200'])}"
            )
            _es = Elasticsearch(
                hosts=es_config.get("hosts", ["127.0.0.1:9200"]),
                verify_certs=es_config.get("ssl_verify", True),
                http_auth=_httpauth,
                api_key=_apikey,
                timeout=30,
                max_retries=10,
                retry_on_timeout=True,
            )

            logger.info("Successfully connected to Elasticsearch")

    return _es


class CSBeaconExtractor(object):
    def __init__(self, config: dict = {}) -> None:
        super().__init__()

        _filtered_config = {
            key: value for key, value in config.items() if key in ["input", "output"]
        }
        self.input_es: Elasticsearch = None
        self.output_es: Elasticsearch = None
        self.config: Cut = Cut(GlobalConfig(**_filtered_config).get_dict())
        logger.debug(f"Parsed config: {self.config}")

        _query_path = os.path.join(
            os.path.dirname(__file__), "data", "cobalt_strike_memory_region_query.json"
        )
        if not os.path.exists(_query_path):
            logger.error(f"Unable to find query JSON at {_query_path}!")
            sys.exit(1)

        with open(_query_path, "rb") as f:
            self.query_json: dict[str, Any] = json.load(f)

        self.idx_json: dict[str, Any] = None
        _idx_settings_path = os.path.join(
            os.path.dirname(__file__), "data", "output_index_settings.json"
        )
        if not os.path.exists(_idx_settings_path):
            logger.error(
                f"Unable to find settings JSON at {_idx_settings_path}! Will skip index setup."
            )
        else:
            with open(_idx_settings_path, "rb") as f:
                self.idx_json = json.load(f)

        self._setup_io()

    def _setup_io(self):
        logger.info("Setting up input/output")

        if self.config["input.elasticsearch.enabled"] is True:
            logger.info("Connecting to Elasticsearch for input")
            self.input_es = _connect_es(self.config["input.elasticsearch"])
            if self.input_es:
                logger.info("Successfully connected to Elasticsearch for input")

            _info = self.input_es.info()
            self.source_info: dict[str, str] = {
                "_cluster_info": {
                    "cluster_name": _info["cluster_name"],
                    "cluster_uuid": _info["cluster_uuid"],
                }
            }
        else:
            self.input_es = None
            logger.error("No supported input is enabled. Please configure the input.")

        if self.config["output.elasticsearch.enabled"] is True:
            logger.info("Connecting to Elasticsearch for output")
            self.output_es = _connect_es(self.config["output.elasticsearch"])
            if self.output_es:
                logger.info("Successfully connected to Elasticsearch for output")
                self._create_idx(self.output_es)

        if self.config["output.console.enabled"] is True:
            self.console = print
            self.console_indent: int = (
                2 if self.config["output.console.pretty"] else None
            )
        else:
            self.console = None

    def _create_idx(self, client):
        """Creates an index in Elasticsearch if one isn't already there."""
        if self.idx_json:
            self.output_es.indices.create(
                index=self.config["output.elasticsearch.index"],
                body=self.idx_json,
                ignore=400,
            )

    def extract(
        self, query_json: dict = None, gte_date: str = None
    ) -> Iterable[dict[str, Any]]:
        """
        This method uses the helpers.scan wrapper from Elasticsearch client and updates
        each dictionary with the source cluster information, which is helpful in larger
        organizations that may have more than once cluster with diagnostic data. This
        method itself is a generator, and yields results downstream.
        """
        if self.input_es:
            if query_json:
                _query = Cut(query_json)
            else:
                _query = Cut(self.query_json)

            if gte_date:
                _datefilter = {
                    "range": {"@timestamp": {"gte": gte_date, "lt": "now/d"}}
                }
                _query["query.bool.filter"].append(_datefilter)

            _results = helpers.scan(
                client=self.input_es,
                index=self.config["input.elasticsearch.index"],
                query=_query,
            )

            for item in _results:
                logger.debug(f"ITEM: {item}")
                yield (item | self.source_info)
        else:
            logger.info("Input is not configured. No results to process.")

    def transform(self, src_docs: Iterable[dict[str, Any]]) -> Iterable[dict[str, Any]]:

        for item in src_docs:
            _src = Cut(item)
            _bytes_compressed = _src[
                "_source.process.Ext.memory_region.bytes_compressed"
            ]
            _payload_bytes = zlib.decompress(base64.b64decode(_bytes_compressed))
            try:
                _beacon = CobaltStrikeConfigParser(_payload_bytes, 4)
                _config = _beacon.parse_config()
            except error.ConfigNotFoundError as e:
                logger.warning(f"CobaltStrike Beacon config not found: {e}")
                continue

            _proc_inject = dict(_config["process-inject"])
            if "stub" in _proc_inject:
                _proc_inject["stub"] = cast(bytes, _proc_inject["stub"]).hex()

            _doc = {
                "@timestamp": _src["_source.@timestamp"],
                "_id": _src["_id"],
                "agent": {
                    "id": _src["_source.agent.id"],
                },
                "event": {
                    "kind": "event",
                    "category": "malware",
                    "type": "info",
                    "xref": {
                        "cluster_name": _src["_cluster_info.cluster_name"],
                        "cluster_uuid": _src["_cluster_info.cluster_uuid"],
                        "index": _src["_index"],
                        "id": _src["_id"],
                    },
                },
                "process": {"args": _src["_source.process.args"]},
                "cobaltstrike": {
                    "beacon_type": _config["beacontype"][0],
                    "cfg_caution": _config["cfg_caution"],
                    "dns_beacon": _config["dns-beacon"],
                    "host_header": _config["host_header"],
                    "http": {
                        "get": _config["http-get"],
                        "post": _config["http-post"],
                    },
                    "jitter": _config["jitter"],
                    "kill_data": _config["kill_date"],
                    "license_id": _config["license_id"],
                    "maxgetsize": _config["maxgetsize"],
                    "pipename": _config["pipename"],
                    "process_inject": _proc_inject,
                    "server": {
                        "hostname": _config["server"]["hostname"],
                        "port": _config["server"]["port"],
                        "public_key": _config["server"]["publickey"].hex(),
                    },
                    "sleep_time": _config["sleeptime"],
                    "smb_frame_header": cast(bytes, _config["smb_frame_header"]).hex()
                    if _config["smb_frame_header"]
                    else None,
                    "spawnto": cast(bytes, _config["spawnto"]).hex(),
                    "spawnto_x64": _config["post-ex"]["spawnto_x64"],
                    "spawnto_x86": _config["post-ex"]["spawnto_x86"],
                    "ssh": _config["ssh"],
                    "stage": _config["stage"],
                    "user_agent": {"original": _config["useragent_header"]},
                },
            }

            logger.debug(f"[DOC] {_doc}")
            _drop_nones(_doc)

            yield _doc

    def load(self, xform_docs: Iterable[dict[str, Any]]) -> Iterable[dict[str, Any]]:

        _successes: int = 0
        _es_docs, _con_docs = tee(xform_docs, 2)

        if self.output_es:
            for ok, action in helpers.streaming_bulk(
                client=self.output_es,
                index=self.config["output.elasticsearch.index"],
                actions=_es_docs,
            ):
                _successes += ok

            logger.info(f"Wrote {_successes} docs to Elasticsearch")

        if self.console:
            for item in _con_docs:
                try:
                    self.console(json.dumps(item, indent=self.console_indent))
                except TypeError as e:
                    logger.error(e)
                    logger.error(f"[ITEM]: {item}")
                    sys.exit(1)

    def run(self):
        _source_docs = self.extract()
        _clean_docs = self.transform(_source_docs)
        self.load(_clean_docs)
