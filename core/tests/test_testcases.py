from core import models
from core.tests.testcases import IntegrationTestCase


class IntegrationTestCaseTest(IntegrationTestCase):
    def test_assertModelEqual_fail(self):
        acc1 = models.Account(address="acc1")
        acc2 = models.Account(address="acc2")

        with self.assertRaisesMessage(
            AssertionError, "Account object (acc1) != Account object (acc2):\n\taddress: acc1 != acc2"
        ):
            self.assertModelEqual(acc1, acc2)
