#!/usr/bin/env python3
import logging
import os
import re
import shutil
import tarfile
import unicodedata
from contextlib import closing
from typing import Any, Optional
from zipfile import ZipFile

import mkdocs
from dirtools2.dirtools2 import Dir
from mkdocs.plugins import BasePlugin

logger = logging.getLogger(__name__)


def slugify(value, allow_unicode=False):
    """
    Convert to ASCII if 'allow_unicode' is False. Convert spaces or repeated
    dashes to single dashes. Remove characters that aren't alphanumerics,
    underscores, or hyphens. Convert to lowercase. Also strip leading and
    trailing whitespace, dashes, and underscores.
    """
    value = str(value)
    if allow_unicode:
        value = unicodedata.normalize("NFKC", value)
    else:
        value = (
            unicodedata.normalize("NFKD", value)
            .encode("ascii", "ignore")
            .decode("ascii")
        )
    value = re.sub(r"[^\w\s-]", "", value.lower())
    return re.sub(r"[-\s]+", "-", value).strip("-_")


def collect_subpages(page):
    def _getpages(item):
        retval = []
        if item.is_section:
            for child in item.children:
                if not child.is_section and not child.is_index:
                    retval.append(child)
                else:
                    retval.extend(_getpages(child))
        return retval

    if page.parent and page.parent.is_section:
        logger.debug(f"Current page {page} has a parent section.")
        page.Pages = _getpages(page.parent)

    return page


def build_tool_bundles(app_config, plugin_config):
    if not plugin_config.get("enabled"):
        return

    _tooldocs = os.path.join(app_config.get("docs_dir", "/docs"), "tools")

    logger.debug(f"Tools docs: {_tooldocs}")
    logger.debug(f"CWD: {os.getcwd()}")
    if not os.path.exists(_tooldocs):
        os.mkdir(_tooldocs)

    logger.info("Building tools bundles")
    _toolsdir = os.path.realpath("./tools")
    with os.scandir(_toolsdir) as it:
        for entry in it:
            if not entry.name.startswith(".") and entry.is_dir():
                if os.path.exists(os.path.join(entry.path, "README.md")):
                    if not os.path.exists(os.path.join(_tooldocs, entry.name)):
                        os.mkdir(os.path.join(_tooldocs, entry.name))

                    shutil.copy(
                        os.path.join(entry.path, "README.md"),
                        os.path.join(_tooldocs, entry.name, "index.md"),
                    )
                    _ignores: Optional[str] = None
                    if os.path.exists(os.path.join(entry.path, ".gitignore")):
                        _ignores = ".gitignore"

                    _dir = Dir(entry.path, exclude_file=_ignores)
                    with closing(
                        tarfile.open(
                            os.path.join(_tooldocs, entry.name, f"{entry.name}.tar.gz"),
                            mode="w:gz",
                        )
                    ) as tar:
                        for root, dirs, files in _dir.walk():
                            for item in files:
                                _path = os.path.realpath(os.path.join(root, item))
                                _arcpath = _path[len(_toolsdir) :]
                                tar.add(_path, arcname=_arcpath)


def build_indicator_bundles(app_config, plugin_config):
    if not plugin_config.get("enabled"):
        return

    logger.info("Building indicator bundles")
    _content = os.path.realpath("./content")
    for root, dirs, files in os.walk(_content):
        for entry in files:
            if entry.endswith("article.md"):
                _artdir = os.path.join(root, os.path.dirname(entry))
                logger.info(f"Processing indicators for {entry} in {_artdir}")

                _ecs: bool = os.path.exists(
                    os.path.join(_artdir, "ecs-indicators.ndjson")
                )
                _stix: bool = os.path.exists(os.path.join(_artdir, "stix-bundle.json"))

                if _ecs or _stix:
                    _archive = os.path.join(_artdir, "indicators.zip")
                    with ZipFile(_archive, "w") as _bundle:
                        if _ecs:
                            _bundle.write(
                                os.path.join(_artdir, "ecs-indicators.ndjson"),
                                arcname="ecs-indicators.ndjson",
                            )
                        if _stix:
                            _bundle.write(
                                os.path.join(_artdir, "stix-bundle.json"),
                                arcname="stix-bundle.json",
                            )

                        _bundle.write(
                            os.path.realpath("./elastic/plugins/README.indicators.md"),
                            arcname="README.md",
                        )


class BuildExtPlugin(BasePlugin):
    config_scheme = (
        ("enabled", mkdocs.config.config_options.Type(bool, default=True)),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def load_config(self, options, config_file_path=None):
        errs, warns = super(BuildExtPlugin, self).load_config(options, config_file_path)

        if not self.config.get("enabled"):
            return errs, warns

        return errs, warns

    def on_env(self, env, config, files, **kwargs):
        env.filters["slugify"] = slugify
        return env

    def on_pre_build(self, config):
        logger.debug("Pre-Build stage")
        build_tool_bundles(config, self.config)
        build_indicator_bundles(config, self.config)

    def on_page_markdown(
        self, markdown: str, page: Any, config: dict[str, Any], files: list[str]
    ):
        logger.debug(f"Page source: {page.file.src_path}")

        _tooldocs = os.path.join(config.get("docs_dir", "docs"), "tools")
        if page.file.src_path.startswith("tools"):
            _dirname = os.path.dirname(page.file.src_path)
            _base = os.path.basename(_dirname)
            _tar = os.path.join(_tooldocs, _base, f"{_base}.tar.gz")
            if os.path.exists(_tar):
                page.meta["download"] = os.path.basename(_tar)

        else:
            logger.debug(
                f'Checking to attach indicator bundle to metadata of {page.meta["title"]}'
            )

            if page.file.dest_path.endswith("article/index.html"):
                _dirname = os.path.dirname(page.file.dest_path)[: -len("article/")]
                _bundle = os.path.join(
                    config.get("docs_dir", "docs"), _dirname, "indicators.zip"
                )

                if os.path.exists(_bundle):
                    _bundle_url = os.path.normpath(
                        os.path.join(
                            os.path.dirname(page.file.url),
                            "..",
                            os.path.basename(_bundle),
                        )
                    ).lstrip(os.sep)

                    logger.debug(
                        f"Indicator bundle exists. Attaching to metadata: {_bundle_url}"
                    )
                    page.meta["indicators_bundle"] = config["site_url"] + _bundle_url

        collect_subpages(page)

        return markdown
