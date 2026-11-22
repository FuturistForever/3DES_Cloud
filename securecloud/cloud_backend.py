"""
Cloud storage abstraction.

The cloud only ever sees opaque, randomly-named encrypted blobs. LocalCloudBackend
stands in for a provider (S3 / Azure Blob / GCS / Drive) using a directory, with an
optional latency + bandwidth simulator so upload/download latency can be evaluated
under realistic network conditions. To use a real provider, subclass CloudBackend
and implement put/get/delete with that provider's SDK (e.g. boto3 upload_file /
download_file); nothing else in the system changes.
"""

import os
import shutil
import time
from abc import ABC, abstractmethod


class CloudBackend(ABC):
    @abstractmethod
    def put(self, blob_id: str, local_path: str) -> None: ...
    @abstractmethod
    def get(self, blob_id: str, local_path: str) -> None: ...
    @abstractmethod
    def delete(self, blob_id: str) -> None: ...


class LocalCloudBackend(CloudBackend):
    def __init__(
        self, root: str, latency_ms: float = 0.0, bandwidth_mbps: float | None = None
    ):
        self.root = root
        self.latency_ms = latency_ms
        self.bandwidth_mbps = bandwidth_mbps
        os.makedirs(root, exist_ok=True)

    def _path(self, blob_id: str) -> str:
        if not blob_id.replace(".", "").replace("_", "").isalnum():
            raise ValueError("invalid blob id")  # no path traversal
        return os.path.join(self.root, blob_id)

    def _simulate(self, nbytes: int) -> None:
        delay = self.latency_ms / 1000.0
        if self.bandwidth_mbps:
            delay += (nbytes * 8) / (self.bandwidth_mbps * 1_000_000)
        if delay:
            time.sleep(delay)

    def put(self, blob_id, local_path):
        shutil.copyfile(local_path, self._path(blob_id))
        self._simulate(os.path.getsize(local_path))

    def get(self, blob_id, local_path):
        p = self._path(blob_id)
        if not os.path.exists(p):
            raise FileNotFoundError(blob_id)
        shutil.copyfile(p, local_path)
        self._simulate(os.path.getsize(p))

    def delete(self, blob_id):
        p = self._path(blob_id)
        if os.path.exists(p):
            os.remove(p)
