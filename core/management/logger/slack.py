import logging

import requests
from django import conf


class SlackHandler(logging.Handler):
    """
    A log handler to publish to registered webhooks
    """

    url = conf.settings.SLACK_DEFAULT_URL

    def emit(self, record: logging.LogRecord):
        from core.soroban import soroban_service

        if not self.url:
            return

        txt = f"*{record.levelname}*:\n```{record.msg}```"
        if record.exc_info:
            txt += f"\n*Traceback*:\n```{self.format(record=record).lstrip(record.msg)}```"

        txt += "\n*Config*:\n"
        txt = {
            "text": txt,
            "attachments": [{"fields": [{"title": k, "value": v} for k, v in soroban_service.set_config().items()]}],
        }

        requests.post(self.url, json=txt, headers={"Content-Type": "application/json"})
