FROM python:3.10-slim AS base

FROM base AS builder

ENV PYTHONFAULTHANDLER=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_CREATE=false \
    PATH="$PATH:/runtime/bin:/root/.local/bin" \
    PYTHONPATH="$PYTHONPATH:/runtime/lib/python3.9/site-packages" \
    POETRY_VERSION="1.2.0b1"

# System deps:
RUN apt-get update && apt-get install -y build-essential unzip python-dev curl
RUN curl -sSL https://install.python-poetry.org \
    | python3 - --preview --version "${POETRY_VERSION}"
RUN python3 -m venv /runtime

# Generate requirements and install dependencies.
COPY pyproject.toml ./
RUN /runtime/bin/pip3 install --upgrade pip && \
    poetry lock --no-plugins && \
    poetry export --no-plugins --without-hashes -f requirements.txt | /runtime/bin/pip3 install -r /dev/stdin

COPY . .
RUN poetry build && /runtime/bin/pip install dist/*.whl

FROM base as runtime
RUN apt-get update && apt-get clean
COPY --from=builder /runtime /runtime

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
