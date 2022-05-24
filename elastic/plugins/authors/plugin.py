from mkdocs.plugins import BasePlugin
from github import Github
import re
from datetime import datetime, timedelta
import pickle
import os

import mkdocs

import logging

logger = logging.getLogger(__name__)

# Permits @ sign prefix, otherwise requires start with letter or digit, followed
# by up to 38 letters, digits, or dashes, but must end with letter or digit, case insensitive
re_name = re.compile(
    "^@?(?P<username>[a-z\d](?:[a-z\d]|-(?=[a-z\d])){0,38})$", re.IGNORECASE
)


class AuthorsPlugin(BasePlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.gh = None
        self.cache = ".cache"
        self.ttl = 1440  # Seconds to cache = 1 day

    config_scheme = (
        ("enabled", mkdocs.config.config_options.Type(bool, default=True)),
    )

    def load_config(self, options, config_file_path=None):
        errs, warns = super(AuthorsPlugin, self).load_config(options, config_file_path)

        if not self.config.get("enabled"):
            return errs, warns

        return errs, warns

    def on_config(self, config):
        if not self.config.get("enabled"):
            return

        # Ensure presence of cache directory
        if not os.path.isdir(self.cache):
            os.makedirs(self.cache)

        _token = None
        if not config.get("github_token"):
            logger.warning("No github_token found. Trying environment.")
            # Try environment for GITHUB_TOKEN
            if "GITHUB_TOKEN" in os.environ:
                _token = os.environ["GITHUB_TOKEN"]
            else:
                logger.warning(
                    "No GITHUB_TOKEN found in environment. Going without auth"
                )
        else:
            _token = config.get("github_token")

        self.gh = Github(_token)

    def _get_author_cache(self, author: str):
        _hash = hex(hash(author))[2:]
        _data = None
        if os.path.exists(os.path.join(self.cache, _hash)):
            with open(os.path.join(self.cache, _hash), "rb") as f:
                _data = pickle.load(f)
                if "expires" in _data:
                    if datetime.now() > datetime.fromisoformat(_data["expires"]):
                        _data = None
        return _data

    def _set_author_cache(self, author: dict):
        _hash = hex(hash(author["username"]))[2:]

        author["expires"] = (datetime.now() + timedelta(seconds=self.ttl)).isoformat()

        with open(os.path.join(self.cache, _hash), "wb") as f:
            pickle.dump(author, f)

    def get_authors(self, authors: list[str]) -> list[dict[str, str]]:
        """Takes a list of github usernames, optionally prefixed with @"""

        _authors: list[dict[str, str]] = []
        for entry in authors:
            _val = self._get_author_cache(entry)
            if _val:
                _authors.append(_val)
                continue

            _match = re_name.match(entry)
            if _match:
                _name = _match["username"]

                if not self.config.get("enabled"):
                    _val = {
                        "name": _name,
                        "url": f"https://github.com/{_name}",
                        "username": _name,
                        "twitter": None,
                        "avatar_url": None,
                    }
                    _authors.append(_val)
                    continue

                try:
                    _u = self.gh.get_user(_name)
                    _val = {
                        "name": _u.name,
                        "url": _u.html_url,
                        "username": _u.login,
                        "twitter": _u.twitter_username,
                        "avatar_url": _u.avatar_url,
                    }
                    self._set_author_cache(_val)
                except Exception as e:
                    logger.error(f"GitHub API Error: {e}")
                    # API exceeded do our best here
                    _val = {
                        "name": _name,
                        "url": f"https://github.com/{_name}",
                        "username": _name,
                        "twitter": None,
                        "avatar_url": None,
                    }

                _authors.append(_val)

        return _authors

    def on_page_markdown(self, markdown, page, config, files):

        if page.meta and "authors" in page.meta:
            _authors = self.get_authors(page.meta["authors"])
            page.meta["authors"] = _authors

        return markdown
