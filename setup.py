# Licensed to Elasticsearch B.V. under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Elasticsearch B.V. licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# 	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

import json
from setuptools import setup, find_packages

# Load package.json contents
with open("package.json") as data:
    package = json.load(data)

# Load list of dependencies
with open("requirements.txt") as data:
    install_requires = [
        line for line in data.read().split("\n") if line and not line.startswith("#")
    ]

# Load README contents
with open("README.md", encoding="utf-8") as data:
    long_description = data.read()

# Package description
setup(
    name="elastic-security-research",
    version=package["version"],
    url=package["homepage"],
    license=package["license"],
    description=package["description"],
    long_description=long_description,
    long_description_content_type="text/markdown",
    author=package["author"]["name"],
    author_email=package["author"]["email"],
    keywords=package["keywords"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "License :: OSI Approved :: ASL 2.0 License",
        "Programming Language :: JavaScript",
        "Programming Language :: Python",
        "Topic :: Documentation",
        "Topic :: Software Development :: Documentation",
        "Topic :: Text Processing :: Markup :: HTML",
    ],
    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    python_requires=">=3.6",
    entry_points={
        "mkdocs.plugins": [
            "authors = elastic.plugins.authors.plugin:AuthorsPlugin",
            "build_ext = elastic.plugins.build_ext.plugin:BuildExtPlugin",
        ]
    },
    zip_safe=False,
)
