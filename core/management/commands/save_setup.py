from django.core.cache import cache
from django.core.management import BaseCommand, call_command
from redis.lock import Lock


class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        """
        used in entrypoint.sh
        prevents race condition between multiple containers running migrate/collectstatic at the same time
        """
        with Lock(cache._cache.get_client(), name="running_setup"):
            call_command("migrate", "--noinput")
            call_command("collectstatic", "--noinput")
