.PHONY: venv build build-image test test clean

SHELL := bash

venv:
	python3 -m venv venv

build:
	pip install --upgrade pip
	pip install -r requirements/dev.txt
	pre-commit install

build-image:
	docker compose build

run-migration:
	@if [ $(use-docker) ]; then \
		docker compose run --rm app sh -c "sleep 15; python manage.py migrate"; \
	else \
		python manage.py migrate; \
	fi;

format:
	black .
	isort .

start-postgres:
	docker compose up -d postgres

start-redis:
	docker compose up -d redis

start-databases: start-redis start-postgres

start-app:
	@if [ $(use-docker) ]; then \
		docker compose up -d app; \
	else \
		source .env; \
		python manage.py runserver; \
	fi;

start-listener:
	./manage.py blockchain_event_listener

start-dev: run-migration start-app

test:
	@if [ $(use-docker) ]; then \
		docker compose run --rm app sh -c "sleep 15; python manage.py migrate"; \
		docker compose run -e "COVERAGE_FILES=$(coverage_files)" --rm app sh bin/run_tests_with_coverage.sh; \
	else \
	  	set -a; source .env; set +a; \
	  	export COVERAGE_FILES=$(shell git diff origin/main --name-only | awk '{print $0}'|  tr '\n' ','); \
		sh bin/run_tests_with_coverage.sh; \
	fi;


test-with-coverage:
	./bin/run_tests_with_coverage.sh

test-unit:
	@./manage.py test -v=3 --tag=unit

test-integration:
	@./manage.py test -v=3 --tag=integration $(arg)

check-style:
	pip install pre-commit
	pre-commit run --all-files --show-diff-on-failure

terminate-django:
	@kill -9 $(runserver_pids) 2> /dev/null || true

clean-docker:
	docker compose down --remove-orphans --volumes

clean-venv:
	rm -rf venv

clean: terminate-django clean-docker clean-venv
