from django.core.management import BaseCommand


class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        from core.soroban import soroban_service

        soroban_service.listen()
