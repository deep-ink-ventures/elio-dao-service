# Elio Dao Service

## Installation
### Setup

```shell
cp .env.example .env
```

Adjust the `.env` values according to your needs, _source_ it, so it is available in your current environment.

```shell
source .env
```

If using zsh (for example, on macOS), you may need to mark variables for export,
before calling any `make` target:

```shell
set -a; source .env; set +a
```

## Quickstart using Docker

```shell
docker compose build
docker compose up
```