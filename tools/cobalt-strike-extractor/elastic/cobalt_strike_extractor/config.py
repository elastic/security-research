import os
from dataclasses import asdict, dataclass, field, fields
from logging import getLogger
from typing import ClassVar, Dict, List, Union, cast, no_type_check

from . import LOGGER_NAME

logger = getLogger(LOGGER_NAME)


@dataclass
class AbstractConfig:
    config_root: ClassVar[str] = "base"

    def __post_init__(self):
        for item in fields(self):
            _path = ".".join([self.config_root, item.name])
            if (
                "environ" in item.metadata
                and not os.environ.get(item.metadata["environ"], None) is None
            ):
                logger.debug(
                    f"Setting {_path} from environment var {item.metadata['environ']}."
                )
                _env_val = os.environ.get(item.metadata["environ"])
                if isinstance(getattr(self, item.name, None), bool):
                    _env_val = _env_val.lower() == "true"
                setattr(self, item.name, _env_val)

        required_fields = (x for x in fields(self) if x.metadata.get("required", False))
        for item in required_fields:
            _path = ".".join([self.config_root, item.name])
            if not getattr(self, item.name, None) and not isinstance(
                getattr(self, item.name, None), bool
            ):
                if (
                    "environ" in item.metadata
                    and os.environ.get(item.metadata["environ"], None) is None
                ):
                    raise ValueError(
                        f"Setting {_path} or environment variable {item.metadata['environ']} must be set!"
                    )
                else:
                    raise ValueError(f"Setting {_path} must be set!")


@dataclass
class ElasticCloudConfig(AbstractConfig):
    auth: str = field(default=None, metadata={"environ": "CLOUD_AUTH"})
    id: str = field(default=None, metadata={"environ": "CLOUD_ID"})


@dataclass
class InputElasticsearchConfig(AbstractConfig):
    config_root: ClassVar[str] = "input.elasticsearch"
    enabled: bool = field(
        default=True, metadata={"environ": "INPUT_ELASTICSEARCH_ENABLED"}
    )

    cloud: ElasticCloudConfig = cast(ElasticCloudConfig, field(default_factory=dict))

    index: str = field(
        default="logs-endpoint.alerts-*",
        metadata={"environ": "INPUT_ELASTICSEARCH_INDEX"},
    )
    hosts: List[str] = field(
        default="",
        metadata={"environ": "INPUT_ELASTICSEARCH_HOSTS"},
    )
    api_key: str = field(
        default=None, metadata={"environ": "INPUT_ELASTICSEARCH_APIKEY"}
    )
    username: str = field(
        default=None, metadata={"environ": "INPUT_ELASTICSEARCH_USERNAME"}
    )
    password: str = field(
        default=None, metadata={"environ": "INPUT_ELASTICSEARCH_PASSWORD"}
    )
    ssl_verify: bool = field(
        default=True, metadata={"environ": "INPUT_ELASTICSEARCH_SSLVERIFY"}
    )

    def __post_init__(self):
        super().__post_init__()
        if isinstance(self.hosts, str):
            self.hosts = self.hosts.split(",")
        self.cloud = ElasticCloudConfig(**self.cloud)


_default_input = {
    "elasticsearch": {
        "hosts": "",
        "ssl_verify": True,
        "index": "logs-endpoint.alerts-*",
        "enabled": True,
    }
}


@dataclass
class InputConfig(AbstractConfig):
    config_root: ClassVar[str] = "input"
    elasticsearch: InputElasticsearchConfig = cast(
        InputElasticsearchConfig, field(default_factory=dict)
    )

    def __post_init__(self):
        self.elasticsearch = InputElasticsearchConfig(
            **(_default_input["elasticsearch"] | self.elasticsearch)
        )


@dataclass
class OutputElasticsearchConfig(AbstractConfig):
    config_root: ClassVar[str] = "output.elasticsearch"
    enabled: bool = field(
        default=True, metadata={"environ": "OUTPUT_ELASTICSEARCH_ENABLED"}
    )

    cloud: ElasticCloudConfig = cast(ElasticCloudConfig, field(default_factory=dict))

    index: str = field(
        default="extraction-cobaltstrike",
        metadata={"environ": "OUTPUT_ELASTICSEARCH_INDEX"},
    )
    hosts: List[str] = field(
        default="",
        metadata={"environ": "OUTPUT_ELASTICSEARCH_HOSTS"},
    )
    api_key: str = field(
        default=None, metadata={"environ": "OUTPUT_ELASTICSEARCH_APIKEY"}
    )
    username: str = field(
        default=None, metadata={"environ": "OUTPUT_ELASTICSEARCH_USERNAME"}
    )
    password: str = field(
        default=None, metadata={"environ": "OUTPUT_ELASTICSEARCH_PASSWORD"}
    )
    ssl_verify: bool = field(
        default=True, metadata={"environ": "OUTPUT_ELASTICSEARCH_SSLVERIFY"}
    )

    def __post_init__(self):
        super().__post_init__()
        if isinstance(self.hosts, str):
            self.hosts = self.hosts.split(",")
        self.cloud = ElasticCloudConfig(**self.cloud)


@dataclass
class OutputConsoleConfig(AbstractConfig):
    config_root: ClassVar[str] = "output.console"
    enabled: bool = field(default=False, metadata={"environ": "OUTPUT_CONSOLE_ENABLED"})
    pretty: bool = field(default=False, metadata={"environ": "OUTPUT_CONSOLE_PRETTY"})


_default_output = {
    "elasticsearch": {
        "hosts": "",
        "ssl_verify": True,
        "index": "extraction-cobaltstrike",
        "enabled": True,
    },
    "console": {"enabled": False},
}


@dataclass
class OutputConfig(AbstractConfig):
    config_root: ClassVar[str] = "output"
    elasticsearch: OutputElasticsearchConfig = cast(
        OutputElasticsearchConfig, field(default_factory=dict)
    )
    console: OutputConsoleConfig = cast(
        OutputConsoleConfig, field(default_factory=dict)
    )

    def __post_init__(self):
        self.elasticsearch = OutputElasticsearchConfig(
            **(_default_output["elasticsearch"] | self.elasticsearch)
        )
        self.console = OutputConsoleConfig(
            **(_default_output["console"] | self.console)
        )


@dataclass
class GlobalConfig:
    input: InputConfig = cast(InputConfig, field(default_factory=dict))
    output: OutputConfig = cast(OutputConfig, field(default_factory=dict))

    def __post_init__(self):
        self.input = InputConfig(**(_default_input | self.input))
        self.output = OutputConfig(**(_default_output | self.output))

    def get_dict(self) -> Dict[str, Dict[str, Union[str, bool, int]]]:
        return _drop_nones(asdict(self))


@no_type_check
def _drop_nones(d: dict) -> dict:
    """Recursively drop Nones in dict d and return a new dict"""
    dd = {}
    for k, v in d.items():
        if isinstance(v, dict):
            dd[k] = _drop_nones(v)
        elif isinstance(v, (list, set, tuple)):
            # note: Nones in lists are not dropped
            dd[k] = type(v)(_drop_nones(vv) if isinstance(vv, dict) else vv for vv in v)
        elif isinstance(v, str) and v:
            dd[k] = v
        elif v is not None:
            dd[k] = v
    return dd
