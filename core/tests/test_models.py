from core import models
from core.tests.testcases import UnitTestCase


class ModelTest(UnitTestCase):
    def test_asset_holding_str(self):
        self.assertEqual(str(models.AssetHolding(asset_id=1, owner_id="acc1", balance=3)), "1 | acc1 | 3")

    def test_block_str(self):
        self.assertEqual(str(models.Block(number=1)), "1")
