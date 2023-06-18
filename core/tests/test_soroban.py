from unittest.mock import patch

from ddt import data, ddt
from django.test import override_settings
from stellar_sdk.soroban.exceptions import RequestException

from core.soroban import soroban_service
from core.tests.testcases import IntegrationTestCase


@ddt
class SorobanTest(IntegrationTestCase):
    @data(
        # start, end, guess
        (0, 15, 5),
        (10, 15, 5),
        (10, 15, 9),
        (10, 15, 10),
        (10, 15, 11),
        (10, 15, 15),
        (10, 15, 16),
        (10, 15, 20),
    )
    @patch("core.soroban.SorobanServer.get_events")
    @patch("core.soroban.logger")
    def test_find_start_ledger(self, case, _, get_events_mock):
        start, end, guess = case

        def get_events(start_ledger):
            if start_ledger < start:
                raise RequestException(0, message="start is before oldest ledger")
            elif start_ledger > end:
                raise RequestException(0, message="start is after newest ledger")
            return "smth"

        get_events_mock.side_effect = get_events

        with override_settings(SOROBAN_START_LEDGER=guess):
            self.assertEqual(soroban_service.find_start_ledger(), start)
        self.assertLess(get_events_mock.call_count, 10)
