from unittest.mock import Mock, patch

from botocore.exceptions import ClientError

from core.file_handling.aws import s3_client
from core.tests.testcases import UnitTestCase


class AWSTest(UnitTestCase):
    def setUp(self):
        self.s3_client = s3_client
        self.s3_client.bucket_name = "bucket1"
        self.s3_client.region_name = "region1"
        self.s3_client.client = Mock()
        self.s3_client.resource = Mock()
        self.file = "file"

    def test_upload_file(self):
        res = self.s3_client.upload_file(file=self.file, storage_destination="store/here")

        self.s3_client.client.upload_fileobj.assert_called_once_with(
            Fileobj=self.file,
            Bucket="bucket1",
            Key="store/here",
            ExtraArgs={"ACL": "public-read"},
        )
        self.assertEqual(res, "https://bucket1.s3.region1.amazonaws.com/store/here")

    @patch("core.file_handling.aws.slack_logger")
    def test_upload_file_fail(self, logger_mock):
        self.s3_client.client.upload_fileobj.side_effect = ClientError({"Error": {"Code": 123}}, "upload_fileobj")
        kwargs = {
            "Fileobj": self.file,
            "Bucket": "bucket1",
            "Key": "store/here",
            "ExtraArgs": {"ACL": "public-read"},
        }

        res = self.s3_client.upload_file(file=self.file, storage_destination="store/here")

        self.s3_client.client.upload_fileobj.assert_called_once_with(**kwargs)
        self.assertEqual(res, "https://bucket1.s3.region1.amazonaws.com/store/here")
        logger_mock.exception.assert_called_once_with(f"Error while uploading a file to s3. {str(kwargs)}")

    def test_delete_file(self):
        self.s3_client.delete_file(storage_destination="some_folder/")

        bucket = self.s3_client.resource.Bucket
        bucket.assert_called_once_with("bucket1")
        bucket().objects.filter.assert_called_once_with(Prefix="some_folder/")
        bucket().objects.filter().delete.assert_called_once_with()

    @patch("core.file_handling.aws.slack_logger")
    def test_delete_file_fail(self, logger_mock):
        self.s3_client.resource.Bucket().objects.filter().delete.side_effect = ClientError(
            {"Error": {"Code": 123}}, "delete"
        )

        self.s3_client.delete_file(storage_destination="some_folder/")

        logger_mock.exception.assert_called_once_with("Error while deleting a file from s3.")
