from django.core.cache import cache
from django.core.management import BaseCommand, call_command
from redis.lock import Lock


class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        with Lock(cache._cache.get_client(), name="running_migrations"):
            call_command("migrate", "--noinput")
