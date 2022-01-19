#!/usr/bin/env python3
import logging
import os
import re
import shutil
import tarfile
import unicodedata
from contextlib import closing
from typing import Any

from dirtools2.dirtools2 import Dir


logger = logging.getLogger(__name__)


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


def on_env(env, config, files, **kwargs):
    env.filters["slugify"] = slugify
    return env


def on_pre_build(config):
    _tooldocs = os.path.join(config.get("docs_dir", "docs"), "tools")

    if not os.path.exists(_tooldocs):
        os.mkdir(_tooldocs)

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
                    _ignores: str = None
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


def on_page_markdown(
    markdown: str, page: dict[str, Any], config: dict[str, Any], files: list[str]
):
    _tooldocs = os.path.join(config.get("docs_dir", "docs"), "tools")
    if page.file.src_path.startswith("tools"):
        _dirname = os.path.dirname(page.file.src_path)
        _base = os.path.basename(_dirname)
        _tar = os.path.join(_tooldocs, _base, f"{_base}.tar.gz")
        if os.path.exists(_tar):
            page.meta["download"] = os.path.basename(_tar)

    collect_subpages(page)

    return markdown
