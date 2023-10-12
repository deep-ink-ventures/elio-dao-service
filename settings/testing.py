from unittest.mock import Mock

from settings.settings import BASE_DIR

TESTING = True
CONFIG_SECRET = "much-secure"

MEDIA_URL = "/test-media/"
MEDIA_ROOT = BASE_DIR / "test-media"

AWS_STORAGE_BUCKET_NAME = None
AWS_S3_ACCESS_KEY_ID = None
AWS_S3_SECRET_ACCESS_KEY = None
AWS_S3_REGION_NAME = None

FILE_UPLOAD_CLASS = "core.file_handling.test.file_handler_mock"
CELERY_TASK_ALWAYS_EAGER = True
RETRY_DELAYS = [0]
SOROBAN_SERVER = Mock()
CORE_CONTRACT_ADDRESS = "CDLUQRW6EXSX4SPXC4WTC3SD5KZE2BHDKPMMKJR4FOPGED4NPKKZ4C4Q"
VOTES_CONTRACT_ADDRESS = "CAPYKFOCLMWWLZRHF65RNARHTMALMBNUPT3EITOEGRZ6TYSA3BV43WMV"
ASSETS_WASM_HASH = "some_assets_wasm_hash"
MULTICLIQUE_WASM_HASH = "some_multiclique_wasm_hash"
POLICY_WASM_HASH = "some_policy_wasm_hash"
SLACK_DEFAULT_URL = "some_slack_default_url"
BLOCKCHAIN_URL = "some_blockchain_url"
NETWORK_PASSPHRASE = "some_network_passphrase"
