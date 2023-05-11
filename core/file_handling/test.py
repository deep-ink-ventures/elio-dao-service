from unittest.mock import Mock


def upload_file(*_args, storage_destination=None, **_kwargs):
    return f"https://some_storage.some_region.com/{storage_destination}"


file_handler_mock = Mock()
file_handler_mock.upload_file.side_effect = upload_file
