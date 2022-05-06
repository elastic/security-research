---
title: BLISTER Configuration Extractor
description: >-
  Python script to extract the configuration and payload from BLISTER samples.
template: tools.html
tags:
  - Tools
  - BLISTER
authors:
  - soolidsnake
---

## Getting Started

This tool provides a Python module and command line tool that will extract configurations from the BLISTER malware loader
 and dump the results to screen.

!!! tip "The BLISTER Malware Loader"

    For information on the BLISTER malware loader and campaign observations, check out our
    blog posts detailing this:

    * [BLISTER Malware Campaign](https://www.elastic.co/blog/elastic-security-uncovers-blister-malware-campaign)
    * [BLISTER Malware Analysis](../../malware/2022/05/02.blister/article.md)

### Docker

We can easily run the extractor with Docker, first we need to build the image:

```bash
docker build . -t blister-config-extractor
```

Then we run the container with the **-v** flag to map a host directory to the docker container directory:

```bash
docker run -ti --rm -v \
"$(pwd)/binaries":/binaries blister-config-extractor:latest -d /binaries/
```

We can either specify a single sample with **-f** option or a directory of samples with **-d**.

<figure markdown>
  ![BLISTER configuration extrator output](../../malware/2022/05/02.blister/media/image41.png "BLISTER configuration extrator output")
<figcaption>BLISTER configuration extrator output</figcaption>
</figure>

### Running it Locally

As mentioned above, Docker is the recommended approach to running this project, however you can also run this locally.
This project uses [Poetry](https://python-poetry.org/) to manage dependencies, testing, and metadata. If you have Poetry
 installed already, from this directory, you can simply run the following commands to run the tool. This will setup a
 virtual environment, install the dependencies, activate the virtual environment, and run the console script.

```bash
poetry lock
poetry install
poetry shell
blister-config-extractor -h
```

Once that works, you can do the same sort of things as mentioned in the Docker instructions above.

## References

- Customised Rabbit cipher implementation based on [Rabbit-Cipher](https://github.com/Robin-Pwner/Rabbit-Cipher/)