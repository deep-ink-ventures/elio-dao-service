#!/bin/sh
coverage run manage.py test || exit $?
coverage xml -o ./coverage-reports/test-coverage-report.xml
msg=$(coverage report --include="${COVERAGE_FILES}")
code=$?
[ "$msg" = "No data to report." ] && exit 0 || echo "$msg"; exit $code
