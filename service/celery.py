import json
import logging
import os

from celery import Celery
from celery.signals import task_failure
from django.utils.timezone import now

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings.settings")

app = Celery("service")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
alerts = logging.getLogger("alerts")


@task_failure.connect
def on_failure(exception, task_id, einfo, traceback, *args, **kwargs):  # noqa
    information = {
        "error": "Task Error",
        "celery_task_id": task_id,
        "exception_class": exception.__class__.__name__,
        "exception_msg": str(exception).strip(),
        "traceback": str(einfo).strip(),
        "occurred_at": now().isoformat(),
        "args": str(args),
        "kwargs": str(kwargs),
    }

    alerts.error(json.dumps(information, indent=2))
