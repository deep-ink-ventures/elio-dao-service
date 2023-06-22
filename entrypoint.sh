#!/bin/sh
set -e

if [  "$1" = "web" ]; then
  python manage.py save_setup
  daphne -b 0.0.0.0 -p 8000 service.asgi:application

elif [ "$1" = "worker" ]; then
  python manage.py save_setup
  set -- celery \
          -A service worker \
          -l INFO \
          -Q celery \
          --autoscale=10,1

elif [ "$1" = "listener" ]; then
  python manage.py save_setup
  python manage.py blockchain_event_listener

fi

exec "$@"
