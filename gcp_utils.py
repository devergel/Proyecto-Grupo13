from google.cloud import storage
import sys
import os


def upload_blob(bucket_name, source_file_name, destination_blob_name):
    """Uploads a file to the google storage bucket."""

    storage_client = storage.Client.from_service_account_json(
        os.environ["AUTH_JSON"])

    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(destination_blob_name)

    blob.upload_from_filename(source_file_name)

    # Make public the blob
    blob.make_public()


def delete_blobs(bucket_name, blob_group):
    """Deletes a blob from the bucket."""

    storage_client = storage.Client.from_service_account_json(
        os.environ["AUTH_JSON"])

    bucket = storage_client.bucket(bucket_name)
    blobs = storage_client.list_blobs('group13_cloud')

    # erase all items with the same ID contest
    for blob in blobs:
        if blob_group in blob.name:
            blob_name = blob.name
            blob.delete()


def download_blob(bucket_name, source_blob_name, destination_file_name):
    """Downloads a blob."""

    storage_client = storage.Client.from_service_account_json(
        os.environ["AUTH_JSON"])

    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(source_blob_name)
    blob.download_to_filename(destination_file_name)
