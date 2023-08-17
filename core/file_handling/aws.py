import logging
from typing import Optional

import boto3
from botocore.exceptions import ClientError
from celery import shared_task

from settings import settings

slack_logger = logging.getLogger("alerts.slack")


class S3Client:
    def __init__(self):
        self.bucket_name = settings.AWS_STORAGE_BUCKET_NAME
        self.region_name = settings.AWS_REGION
        s3_credentials = {
            "service_name": "s3",
            "aws_access_key_id": settings.AWS_S3_ACCESS_KEY_ID,
            "aws_secret_access_key": settings.AWS_S3_SECRET_ACCESS_KEY,
            "region_name": self.region_name,
        }
        self.client = boto3.client(**s3_credentials)
        self.resource = boto3.resource(**s3_credentials)

    @staticmethod
    @shared_task(serializer="pickle")
    def _upload_file(**kwargs):
        try:
            s3_client.client.upload_fileobj(**kwargs)
        except ClientError:
            slack_logger.exception(f"Error while uploading a file to s3. {kwargs}")

    def upload_file(self, file, storage_destination) -> Optional[str]:
        """
        Args:
            file: file to upload (file-like obj, readable)
            storage_destination: e.g.: folder1/folder2/filename.jpeg

        Returns:
            url of uploaded file

        uploads file to s3
        """
        self._upload_file.delay(
            Fileobj=file, Bucket=self.bucket_name, Key=storage_destination, ExtraArgs={"ACL": "public-read"}
        )
        return f"https://{self.bucket_name}.s3.{self.region_name}.amazonaws.com/{storage_destination}"

    def delete_file(self, storage_destination):
        """
        Args:
            storage_destination: e.g.: 'folder1/'

        deletes file from s3
        """
        try:
            self.resource.Bucket(self.bucket_name).objects.filter(Prefix=storage_destination).delete()
        except ClientError:
            slack_logger.exception("Error while deleting a file from s3.")


s3_client = S3Client()
