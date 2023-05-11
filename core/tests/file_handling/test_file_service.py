import json
from io import BytesIO
from unittest.mock import ANY, call, patch

from ddt import data, ddt
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.test import override_settings

from core.file_handling.file_handler import (
    FileHandler,
    HashMismatchException,
    file_handler,
)
from core.tests.testcases import UnitTestCase


@ddt
class FileHandlerTest(UnitTestCase):
    def test_invalid_encryption_algorithm(self):
        with override_settings(ENCRYPTION_ALGORITHM="non_existent"), self.assertRaisesMessage(
            Exception, "'non_existent' is not a valid hashlib encryption algorithm."
        ):
            FileHandler()

    def test_invalid_file_upload_class(self):
        with override_settings(FILE_UPLOAD_CLASS="non_existent"), self.assertRaisesMessage(
            Exception, "non_existent doesn't look like a module path"
        ):
            FileHandler()

    @data(
        # input_data, expected_hash
        ({"a": 1}, "595dbdd6cebd2cce5e81b4bd45d9ad1488e44179efa14f8f1fd6cad5f53e4735"),  # noqa
        ({"b": 2}, "97ed12383ce30593e8b53795638b600599deda8ff3a79f02ef0c672639a2e380"),  # noqa
    )
    def test__hash(self, case):
        input_data, expected_hash = case

        self.assertEqual(file_handler._hash(json.dumps(input_data).encode()), expected_hash)

    @data(
        # file extension
        "jpg",
        "jpeg",
    )
    def test_upload_metadata(self, file_extension):
        file = InMemoryUploadedFile(
            file=open("core/tests/test_file.jpeg", "rb"),
            name=f"testfile.{file_extension}",
            field_name="file",
            size="0",
            content_type="image/jpeg",
            charset=None,
        )
        metadata = {
            "logo": file,
            "some": "other",
            "interesting": "data",
        }

        res = file_handler.upload_dao_metadata(metadata=metadata, storage_destination="store/here")

        file_handler.file_upload_class.upload_file.assert_has_calls(
            [
                call(file=ANY, storage_destination="store/here/logo_small.jpeg"),
                call(file=ANY, storage_destination="store/here/logo_medium.jpeg"),
                call(file=ANY, storage_destination="store/here/logo_large.jpeg"),
                call(file=ANY, storage_destination="store/here/metadata.json"),
            ]
        )
        self.assertDictEqual(
            res,
            {
                "metadata": {
                    "images": {
                        "logo": {
                            "content_type": "image/jpeg",
                            "large": {"url": "https://some_storage.some_region.com/store/here/logo_large.jpeg"},
                            "medium": {"url": "https://some_storage.some_region.com/store/here/logo_medium.jpeg"},
                            "small": {"url": "https://some_storage.some_region.com/store/here/logo_small.jpeg"},
                        }
                    },
                    "some": "other",
                    "interesting": "data",
                },
                "metadata_hash": "491a300727047f4ac6d0ecf87629904292e8b38ae6e19c40947dabeffb78214a",  # noqa
                "metadata_url": "https://some_storage.some_region.com/store/here/metadata.json",
            },
        )
        file.close()

    @patch("core.file_handling.file_handler.urlopen")
    def test_download_metadata(self, urlopen_mock):
        expected_data = {"a": 1}
        file = BytesIO(json.dumps(expected_data).encode())
        urlopen_mock.return_value = file
        metadata_hash = file_handler._hash(file.getvalue())

        res = file_handler.download_metadata(url="some_url", metadata_hash=metadata_hash)

        urlopen_mock.assert_called_once_with("some_url")
        self.assertDictEqual(res, expected_data)

    @patch("core.file_handling.file_handler.urlopen")
    def test_download_metadata_hash_mismatch(self, urlopen_mock):
        expected_data = {"a": 1}
        file = BytesIO(json.dumps(expected_data).encode())
        urlopen_mock.return_value = file
        metadata_hash = "not it"

        with self.assertRaises(HashMismatchException):
            self.assertIsNone(file_handler.download_metadata(url="some_url", metadata_hash=metadata_hash))

        urlopen_mock.assert_called_once_with("some_url")
