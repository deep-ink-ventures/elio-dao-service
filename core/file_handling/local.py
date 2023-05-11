from typing import Optional

from django.core.files.storage import FileSystemStorage


class OverwriteStorage(FileSystemStorage):
    def _save(self, name, content):
        self.delete(name)
        return super()._save(name, content)

    def get_available_name(self, name, max_length=None):
        return name


class LocalStorage:
    def __init__(self):
        self.storage = OverwriteStorage()

    def upload_file(self, file, storage_destination) -> Optional[str]:
        """
        Args:
            file: file to upload (file-like obj, readable)
            storage_destination: e.g.: folder1/folder2/filename.jpeg

        Returns:
            url of uploaded file

        uploads file to s3
        """
        return self.storage.base_url + self.storage.save(storage_destination, file)


storage = LocalStorage()
