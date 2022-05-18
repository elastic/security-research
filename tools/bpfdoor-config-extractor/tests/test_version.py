from importlib.metadata import version


def test_version():
    assert version("elastic.bpfdoor_extractor") == "1.0.0"
