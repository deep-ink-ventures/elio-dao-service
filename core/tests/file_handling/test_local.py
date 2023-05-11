import filecmp

from django.core.files.uploadedfile import InMemoryUploadedFile

from core.file_handling.local import storage
from core.tests.testcases import UnitTestCase


class LocalStorageTest(UnitTestCase):
    def tearDown(self):
        storage.storage.delete("store/here.jpeg")
        storage.storage.delete("store")

    def test_upload_file(self):
        file_path = "core/tests/test_file.jpeg"
        file = InMemoryUploadedFile(
            file=open(file_path, "rb"),
            name="testfile.jpeg",
            field_name="file",
            size="0",
            content_type="image/jpeg",
            charset=None,
        )
        storage_destination = "store/here.jpeg"

        file_name = storage.upload_file(file=file, storage_destination=storage_destination)

        self.assertTrue(filecmp.cmp(file_name.lstrip("/"), file_path))
