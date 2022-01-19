import json
import logging
import os
from unittest import mock

from elastic.cobalt_strike_extractor.extractor import CSBeaconExtractor

logger = logging.getLogger()


def test_transform_beacon(shared_datadir):
    with mock.patch.dict(
        os.environ,
        {
            "INPUT_ELASTICSEARCH_ENABLED": "False",
            "OUTPUT_ELASTICSEARCH_ENABLED": "False",
            "OUTPUT_CONSOLE_ENABLED": "True",
        },
    ):

        _extractor = CSBeaconExtractor()
        _docs = (shared_datadir / "sample_raw_docs.ndjson").read_text().strip()
        _control_docs = (
            (shared_datadir / "sample_transformed_docs.ndjson").read_text().strip()
        )

        _data = []
        for item in _docs.split("\n"):
            _data.append(json.loads(item))

        _control_data = []
        for item in _control_docs.split("\n"):
            _control_data.append(json.loads(item))

        _results = _extractor.transform(_data)
        _results = list(_results)

        assert len(_results) == len(_control_data)

        _zip = zip(_results, _control_data)
        for item1, item2 in _zip:
            assert item1 == item2
