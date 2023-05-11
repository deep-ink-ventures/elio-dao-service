# noinspection PyPackageRequirements
from storages.backends.s3boto3 import S3Boto3Storage


class S3StaticStorage(S3Boto3Storage):
    def get_default_settings(self):
        settings = super().get_default_settings()
        settings["default_acl"] = "public-read"
        settings["querystring_auth"] = False
        return settings
