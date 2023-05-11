import hashlib
import json
import shutil
from io import BytesIO
from urllib.request import urlopen

from django.conf import settings
from django.utils.module_loading import import_string
from PIL import Image


class HashMismatchException(Exception):
    pass


class FileHandler:
    file_upload_class = None
    encryption_algorithm = None

    def __init__(self):
        self.file_upload_class = import_string(settings.FILE_UPLOAD_CLASS)
        try:
            self.encryption_algorithm = getattr(hashlib, settings.ENCRYPTION_ALGORITHM)
        except AttributeError:
            raise Exception(f"'{settings.ENCRYPTION_ALGORITHM}' is not a valid hashlib encryption algorithm.")

    def _hash(self, data: bytes) -> str:
        return self.encryption_algorithm(data).hexdigest()

    def upload_metadata(self, metadata: dict, storage_destination: str) -> dict:
        """
        Args:
             metadata: metadata to upload, has to contain logo:InMemoryUploadedFile
             storage_destination: pathstr / folder name. e.g.: "folder_1/folder_2/my_file.jpeg"

        Returns:
             metadata dict e.g.:
             {
                 "metadata": {"some": "data"},
                 "metadata_hash": "ecda2de0cb7a7f293072a18ac088d5ce6595328e29d6174425e7949f7c2829da",
                 "metadata_url": "https://some_bucket.s3.some_region.amazonaws.com/some_folder/metadata.json",
             }

        uploads the metadata using the file upload class' (provided via envvar FILE_UPLOAD_CLASS) upload_file
        method to the given 'storage_destination', e.g. Dao.id.
        """
        encoded_metadata = json.dumps(metadata, indent=4).encode()
        io = BytesIO(encoded_metadata)
        io.seek(0)
        return {
            "metadata": metadata,
            "metadata_hash": self._hash(encoded_metadata),
            "metadata_url": self.file_upload_class.upload_file(
                file=io, storage_destination=f"{storage_destination}/metadata.json"
            ),
        }

    def upload_dao_metadata(self, metadata: dict, storage_destination: str) -> dict:
        """
        Args:
            metadata: metadata to upload, has to contain logo:InMemoryUploadedFile
            storage_destination: pathstr / folder name. e.g.: "folder_1/folder_2/my_file.jpeg"

        Returns:
            metadata dict e.g.:
            {
                "metadata": {
                    "description_short": "short description",
                    "description_long": "long description",
                    "email": "some@email",
                    "images": {
                        "logo": {
                            "content_type": "image/jpeg",
                            "small": {
                                "url": "https://some_bucket.s3.some_region.amazonaws.com/some_folder/logo_small.jpeg",
                            },
                            "medium": ...,
                        }
                    },
                },
                "metadata_hash": "ecda2de0cb7a7f293072a18ac088d5ce6595328e29d6174425e7949f7c2829da",
                "metadata_url": "https://some_bucket.s3.some_region.amazonaws.com/some_folder/metadata.json",
            }

        creates 3 files by resizing the logo to small, medium and large; size specified in envvar LOGO_SIZES.
        uploads the resized files to a 'storage_destination', e.g. Dao.id.
        """  # noqa
        # derive format from file extension
        logo = metadata.pop("logo")
        _format = logo.name.split(".")[-1]
        if _format == "jpg":
            _format = "jpeg"
        metadata = {**metadata, "images": {"logo": {"content_type": logo.content_type}}}
        with Image.open(logo) as img:
            for size_name, dimensions in settings.LOGO_SIZES.items():
                io = BytesIO()
                img.resize(dimensions).save(io, format=_format)
                io.seek(0)
                url = self.file_upload_class.upload_file(
                    file=io, storage_destination=f"{storage_destination}/logo_{size_name}.{_format}"
                )
                metadata["images"]["logo"][size_name] = {"url": url}

        return self.upload_metadata(metadata=metadata, storage_destination=storage_destination)

    def download_metadata(self, url: str, metadata_hash: str) -> dict:
        """
        Args:
            url: url to download the metadata.json from
            metadata_hash: hash of the metadata.json

        Returns:
            metadata dict

        Raises:
            HashMismatchException

        downloads the metadata.json from the given url and compares its hash to given metadata_hash.
        returns metadata dict on match, raises on mismatch.
        """
        metadata = BytesIO()
        with urlopen(url) as response:
            shutil.copyfileobj(response, metadata)
        if self._hash(metadata.getvalue()) != metadata_hash:
            raise HashMismatchException
        return json.loads(metadata.getvalue().decode())


file_handler = FileHandler()
