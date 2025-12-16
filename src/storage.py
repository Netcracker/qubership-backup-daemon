# Copyright 2024-2025 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from abc import ABC, abstractmethod
from functools import total_ordering
import os
from datetime import datetime
import logging
from traceback import format_exception
import time
import json

import boto3
from botocore.exceptions import ClientError
from botocore import config
import fsutil
import re
import io

SKIP_LOCK_CHECK = os.getenv("SKIP_LOCK_CHECK", "false").lower() == "true"


class StorageLocationAlreadyExistsException(Exception):
    pass

class FileSystem:

    def exists(self, path, type="dir"):
        return os.path.exists(path)

    def makedirs(self, path):
        if not os.path.exists(path):
            return os.makedirs(path)

    def listdir(self, path):
        return os.listdir(path)

    def read_file(self, path, log):
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except IOError as e:
            log.warning(f'I/O error({e.errno}): {e.strerror}')
            return {}

    def remove(self, path):
        if os.path.exists(path):
            os.remove(path)

    def rmdir(self, path):
        if os.path.exists(path):
            os.rmdir(path)

    def basename(self, path):
        return os.path.basename(path)

    def walk(self, path, topdown=False):
        return os.walk(path, topdown=topdown)

    def join(self, path, name):
        return os.path.join(path, name)

    def touch(self, path):
        fsutil.touch(path)

    def unlink(self, path):
        os.unlink(path)

    def rmtree(self, path):
        if os.path.exists(path):
            fsutil.rmtree(path)

    def get_type(self):
        return "fs"


class S3Client:
    __log = logging.getLogger("S3Client")

    def __init__(self, url, bucket_name, access_key_id: str=None,
                 access_key_secret: str=None, ssl_verify=False):
        """
        S3Client with access to client itself and resource object
        """
        self.url = url
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.bucket_name = bucket_name

        client_config = config.Config(
            region_name="auto",
            max_pool_connections=int(os.getenv("NC_S3_MAX_POOL", 30)),
        )

        self.client = boto3.client(
            "s3",
            endpoint_url=url,
            aws_access_key_id=access_key_id,
            aws_secret_access_key=access_key_secret,
            config=client_config,
            verify=ssl_verify,
        )

        self.resource = boto3.resource(
            "s3",
            region_name="auto",
            endpoint_url=self.url,
            aws_access_key_id=self.access_key_id,
            aws_secret_access_key=self.access_key_secret,
            verify=ssl_verify
        )

    def create_presigned_url(self, object_name, expiration=3600):
        """Generate a presigned URL to share an S3 object

        :param bucket_name: string
        :param object_name: string
        :param expiration: Time in seconds for the presigned URL to remain valid
        :return: Presigned URL as string. If error, returns None.
        """

        if expiration is None:
            expiration = 3600
        try:
            response = self.client.generate_presigned_url('get_object',
                                                        Params={'Bucket': self.bucket_name,
                                                                'Key': object_name},
                                                        ExpiresIn=expiration)
        except ClientError as e:
            logging.error(e)
            return None

        # The response contains the presigned URL
        return response

    def list_files(self, path):
        path = path.strip("/")
        files = []
        objects = self.client.list_objects_v2(Bucket=self.bucket_name, Prefix=path).get(
            'Contents', [])
        for obj in objects:
            files.append(obj['Key'])
        return files

    def upload_folder(self, path, dest_root=None):
        for root, dirs, files in os.walk(path, topdown=False):
            for name in files:
                src = os.path.join(root, name)
                if dest_root:
                    rel = os.path.relpath(src, path)        
                    dest = os.path.join(dest_root, rel)       
                else:
                    dest = src
                self.upload_file(src, dest)

    def upload_file(self, src, dest: str=None):
        if dest is None:
            dest = src
        dest = dest.strip("/")
        self.client.upload_file(src, self.bucket_name, dest)
        self.__log.info(f"Uploading file {src} to S3 {dest}")

    def download_file(self, src, dest):
        src = src.strip("/")
        self.client.download_file(self.bucket_name, src, dest)
        self.__log.info(f"Downloading file {src} uploaded from S3 to {dest}")

    def download_folder(self, s3_folder, local_dir=None):
        self.__log.info(f"start saving {s3_folder}")
        s3_folder = s3_folder.strip("/")
        """
        Download the contents of a folder directory
        Args:
            s3_folder: the folder path in the s3 bucket
            local_dir: a relative or absolute directory path in the local file system
        """
        bucket = self.resource.Bucket(self.bucket_name)
        for obj in bucket.objects.filter(Prefix=s3_folder):
            target = os.path.join("/", obj.key) if local_dir is None \
                else os.path.join(local_dir, os.path.relpath(obj.key, s3_folder))
            if not os.path.exists(os.path.dirname(target)):
                os.makedirs(os.path.dirname(target))
            if obj.key[-1] == '/':
                continue
            bucket.download_file(obj.key, target)
        
        self.__log.info(f"finished saving {s3_folder}")


class S3FileSystem(FileSystem):
    __log = logging.getLogger("Storage")

    def __init__(self, client: S3Client):
        self.s3client = client

    def listdir(self, path):
        dirs = []
        path = path.strip("/")
        path = path + "/"
        try:
            res = self.s3client.client.list_objects_v2(Bucket=self.s3client.bucket_name, Prefix=path, Delimiter="/")
            for prefix in res.get('CommonPrefixes', []):
                split_prefix = prefix["Prefix"].strip("/").split("/")
                if VAULT_DIRNAME_MATCHER.match(split_prefix[-1]):
                    dirs.append(split_prefix[-1])    
        except ClientError as e:
            self.__log.error(f'Could not list files from path {path}, error message {e}')
            raise e
        return dirs

    def exists(self, path, type="dir"):
        path = path.strip("/")
        if type == "dir":
            resp = self.s3client.client. \
                list_objects(Bucket=self.s3client.bucket_name, Prefix=path, MaxKeys=1)
            return 'Contents' in resp
        elif type == "file":
            try:
                self.s3client.resource.Object(self.s3client.bucket_name, path).load()
            except ClientError as e:
                if e.response['Error']['Code'] == "404":
                    return False
                else:
                    self.__log.error(f'Could not check if file exists from path {path}, error message: {e}')
                    raise e
            return True

    def makedirs(self, path):
        super().makedirs(path)

    def read_file(self, path, log):
        path = path.strip("/")
        try:
            response = self.s3client.client.get_object(Bucket=self.s3client.bucket_name, Key=path)
            return json.loads(response['Body'].read())
        except ClientError as e:
            log.warning(f'Could not read file from path {path}, error message: {e}')
            return {}

    def remove(self, path):
        super().remove(path)
        path = path.strip("/")
        bucket = self.s3client.resource.Bucket(self.s3client.bucket_name)
        # does not work in google
        # bucket.objects.filter(Prefix=path).delete()
        objs = bucket.objects.filter(Prefix=path).all()

        try:
            for obj in objs:
                obj.delete()
        except ClientError as e:
            self.__log.warn(f"Could not delete files from path {path}, error message: {e}")

        # to delete all versions if s3 cluster replication is enabled
        try:
            bucket.object_versions.filter(Prefix=path).delete()
            self.__log.debug(f"Permanently deleted all versions of object {path}.")
        except ClientError as e:
            self.__log.warn(f"Couldn't delete all versions of {path}. {e}")

    def rmdir(self, path):
        super().rmdir(path)
        self.remove(path)

    def touch(self, path):
        path = path.strip("/")
        self.s3client.client.put_object(Bucket=self.s3client.bucket_name, Key=path)

    def unlink(self, path):
        self.remove(path)

    def rmtree(self, path):
        super().rmtree(path)
        self.remove(path)

    def get_type(self):
        return "s3"

# if you change vault name format here, also change it in scheduler
VAULT_NAME_FORMAT = "%Y%m%dT%H%M%S"
VAULT_DIRNAME_MATCHER = re.compile("\\d{8}T\\d{4,6}", re.IGNORECASE)
FULL = 'full'
GRANULAR = 'granular'
SHARDED = 'sharded'


class Storage(object):
    __log = logging.getLogger("Storage")

    def __init__(self, root, external_root=None, file_system=FileSystem(), allow_prefix=False):
        self.__log.info("Init storage object with storage root: %s external root: %s" % (root, external_root))
        self.root = root
        self.namespace = os.getenv("WATCH_NAMESPACE", "")
        self.file_system = file_system
        self.granular_folder = self.root + "/" + GRANULAR
        self.restore_logs_folder = self.root + "/restore_logs"
        self.s3_enabled = isinstance(file_system, S3FileSystem)
        self.allow_prefix = allow_prefix

        if external_root is not None:
            self.external_root = external_root

        if not self.file_system.exists(self.granular_folder):
            self.file_system.makedirs(self.granular_folder)
        if not file_system.exists(self.restore_logs_folder):
            self.file_system.makedirs(self.restore_logs_folder)

    def get_vault_name(self, prefix, is_granular):
        if not is_granular or not self.namespace or not self.allow_prefix:
            return datetime.now().strftime(VAULT_NAME_FORMAT)
        vault_name = ""
        if prefix:
            vault_name += prefix + "_"
        vault_name += self.namespace + "_" + datetime.now().strftime(VAULT_NAME_FORMAT)
        return vault_name

    def get_nonevictable_vaults(self):
        return [vault for vault in self.list() if vault.is_nonevictable()]

    def get_vault(self, vault_name, external=False, vault_path=None, blob_path=None, skip_fs_check=False):
        self.__log.debug("Get vault name = %s external = %s" % (vault_name, external))
        self.__log.debug("vault path = %s " % vault_path)
        try:
            if not external:
                if skip_fs_check:
                    return Vault(self.root + "/" + vault_name, file_system=self.file_system)
                if self.file_system.exists(self.root):
                    if self.file_system.exists(self.root + "/" + vault_name):
                        return Vault(self.root + "/" + vault_name, file_system=self.file_system)
                    
                    if blob_path and self.file_system.exists(self.granular_folder + "/" + blob_path.strip("/") + "/" + vault_name):
                        return Vault(self.granular_folder + "/" + blob_path.strip("/") + "/" + vault_name,
                                    file_system=self.file_system)
                    
                    if self.file_system.exists(self.granular_folder + "/" + vault_name):
                        return Vault(self.granular_folder + "/" + vault_name, file_system=self.file_system)
                    
            elif vault_path is not None:
                self.__log.debug("Get vault external")
                if self.file_system.exists(self.external_root):
                    self.__log.debug(
                        "Get vault concated path " + self.external_root + "/" + vault_path + "/" + vault_name)
                    if self.file_system.exists(self.external_root + "/" + vault_path + "/" + vault_name):
                        self.__log.debug("Get vault vault path exists")
                        return Vault(self.external_root + "/" + vault_path + "/" + vault_name, external=external)
        except:
            return None
        return None

    def list(self, timestamps_only=False, convert_to_ts=False, type="all", storage_path=None):
        # returns all vaults if type=all
        # only granular if type=granular
        # only full if type=full
        if storage_path is None:
            storage_root_path = self.root
        else:
            storage_root_path = self.external_root + "/" + storage_path
        if self.file_system.exists(storage_root_path):
            if type == GRANULAR:
                dirs = [f'{GRANULAR}/{x}' for x in self.file_system.listdir(storage_root_path + "/" + GRANULAR)]
            elif type == FULL or "inc-backup-storage" in storage_root_path:
                dirs = self.file_system.listdir(storage_root_path)
            else:
                dirs = self.file_system.listdir(storage_root_path) + [GRANULAR + '/' + x for x in
                                                                      self.file_system.listdir(
                                                                          storage_root_path + "/" + GRANULAR)]

            self.__log.debug("Listing vaults for dirs: %s" % dirs)
            vaults = [
                self.get_vault(dirname, storage_path is not None, storage_path, skip_fs_check=True)
                for dirname in dirs
                if VAULT_DIRNAME_MATCHER.match(dirname.split("_")[-1:][0].replace(GRANULAR + '/', '')) is not None
            ]

            if type == SHARDED:
                vaults = [v for v in vaults if v.is_sharded()]

            if not SKIP_LOCK_CHECK:
                vaults = [v for v in vaults if v and not v.is_locked()]

            vaults.sort(key=lambda v: v.create_time())
            self.__log.debug("Listing vaults: %s" % vaults)
            if timestamps_only:
                return [vault.create_timestamp_sec() if convert_to_ts else vault.get_name() for vault in vaults]
            else:
                return vaults
        else:
            return []

    def find_by_ts(self, timestamp, type="all", storage_path=None):
        # finds in all vaults if type=all
        # only granular if type=granular
        # only full if type=full
        # returns vault name with ts newer or equal to ts, else None
        vaults = self.list(type=type, storage_path=storage_path)
        try:
            converted_timestamp = int(timestamp)
        except ValueError:
            self.__log.warning(
                "ValueError: timestamp %s is in incorrect format" % timestamp)
            return None
        for vault in vaults:
            if vault.create_timestamp() >= converted_timestamp:
                return vault.get_name()
        return None

    def size(self):
        """ Returns whole storage size in bytes """
        return fsutil.get_folder_size(self.root)

    def get_fs_type(self):
        return self.file_system.get_type()

    def fs_space(self):
        """ Returns dict (free_space, total_space, free_inodes, total_inodes)
        on mount point where is root folder located """
        return fsutil.get_fs_space(self.root)

    def open_vault(self, vault_name=None, allow_eviction=True, is_granular=False, is_sharded=False,
                   is_external=False, vault_path=None, backup_prefix=None, blob_path=None):
        vault = self.get_vault(vault_name, is_external, vault_path, blob_path=blob_path)
        self.__log.info(vault)
        if vault is not None:
            return vault
        else:
            result = (None, None, None)
            if is_granular:
                self.__log.debug("Creating granular vault: %s" % vault_name)
                folder = self.granular_folder
                if blob_path:
                    folder = folder + "/" + blob_path.strip("/")
            else:
                self.__log.debug("Creating full vault: %s" % vault_name)
                if not is_external:
                    folder = self.root
                else:
                    folder = self.external_root + "/" + vault_path
            if not vault_name:
                try:
                    result = Vault("%s/%s" % (folder, self.get_vault_name(backup_prefix, is_granular)),
                                   allow_eviction, is_sharded, file_system=self.file_system)
                except StorageLocationAlreadyExistsException as e:
                    # sleep 2 secs if vault exists
                    time.sleep(2)
                    try:
                        result = Vault("%s/%s" % (folder, self.get_vault_name(backup_prefix, is_granular)),
                                       allow_eviction, is_sharded, file_system=self.file_system)
                    except StorageLocationAlreadyExistsException as e:
                        logging.error(str(e))
            else:
                try:
                    result = Vault("%s/%s" % (folder, vault_name), allow_eviction, is_sharded, file_system=self.file_system)
                except StorageLocationAlreadyExistsException as e:
                    logging.error(str(e))

        return result

    def tail_restore_log(self, uuid, lines=5):
        return fsutil.tail(self.restore_logs_folder + "/" + uuid + ".log", lines)

    def evict(self, vault):
        self.__log.info("Evict vault: %s, is granular: %s" % (vault, vault.is_granular()))
        self.__log.info("Evict vault: %s, is sharded: %s" % (vault, vault.is_sharded()))

        self.__log.debug("Delete folder: %s" % vault.folder)
        self.file_system.rmtree(vault.folder)

    def prot_get_as_stream(self, backup_id, archive_file):
        """
        :param backup_id: path to file from backup root.
        :type backup_id: string
        :param archive_file: name of the backup archive file
        :type archive_file: string
        :return: stream with requested file
        :rtype: io.RawIOBase
        """
        backup_folder = self.get_vault(backup_id).folder
        self.__log.info("Get request for file: %s" % backup_id)
        full_file_path = self.file_system.join(backup_folder, archive_file)
        self.__log.info("full file path: %s" % full_file_path)
        return io.FileIO(full_file_path, "r", closefd=True)


@total_ordering
class Vault(object):
    __log = logging.getLogger("VaultLock")
    def __init__(self, folder, allow_eviction=True, sharded=False, external=False,
                 file_system=FileSystem()):
        self.folder = folder
        self.fileSystem = file_system
        self.metrics_filepath = self.folder + "/.metrics"
        self.custom_vars_filepath = self.folder + '/.custom_vars'
        self.__is_evictable = allow_eviction
        self.__is_sharded = sharded
        self.__external = external
        self.__timestamp = self.create_time()
        self.metrics = {}

    def load_metrics(self):
        self.__log.debug("Load metrics from: %s" % self.metrics_filepath)
        return self.fileSystem.read_file(self.metrics_filepath, self.__log)

    def store_metrics(self, exception=None):
        self.__log.info(f'Save metrics to: {self.metrics_filepath}')
        self.metrics["spent_time"] = int(time.time() * 1000) - self.start_timestamp

        self.metrics["size"] = fsutil.get_folder_size(self.folder)

        if not exception:
            self.__log.info(f'Unlock vault: {self.folder}')
        else:
            self.fileSystem.touch(self.__failed_filepath())

            self.__log.info("Don't remove vault .lock due exception in nested code")
            self.__log.debug(f'Something wrong happened inside block uses vault: {exception}')
            self.metrics["exception"] = exception

        with open(self.metrics_filepath, "w") as f:
            return json.dump(self.metrics, f)

    def load_custom_variables(self):
        self.__log.debug(f'Load custom variables from: {self.custom_vars_filepath}')
        return self.fileSystem.read_file(self.custom_vars_filepath, self.__log)

    def store_custom_variables(self, custom_variables):
        self.__log.info(f'Save custom variables to: {self.custom_vars_filepath}')
        with open(self.custom_vars_filepath, 'w') as f:
            return json.dump(custom_variables, f)

    def lock_filepath(self):
        return self.folder + "/.lock"

    def nonevictablelock_filepath(self):
        return self.folder + "/.evictlock"

    def sharded_filepath(self):
        return self.folder + "/.sharded"

    def __failed_filepath(self):
        return self.folder + "/.failed"

    def canceled_filepath(self):
        return self.folder + "/.canceled"

    def is_locked(self):
        return self.fileSystem.exists(self.lock_filepath())

    def is_nonevictable(self):
        return self.fileSystem.exists(self.nonevictablelock_filepath())

    def is_sharded(self):
        return self.fileSystem.exists(self.sharded_filepath())

    def is_failed(self):
        return self.fileSystem.exists(self.__failed_filepath())

    def is_canceled(self):
        return self.fileSystem.exists(self.canceled_filepath())

    def has_custom_vars(self):
        return self.fileSystem.exists(self.custom_vars_filepath)

    def is_granular(self):
        # returns True if granular backup, False if full
        return self.folder.find(GRANULAR) >= 0

    def __enter__(self):
        self.__log.info("Init next vault: %s" % self.folder)
        self.start_timestamp = int(time.time() * 1000)

        if not self.fileSystem.exists(self.folder):
            self.fileSystem.makedirs(self.folder)
        elif not self.__external:
            raise StorageLocationAlreadyExistsException("Destination backup folder already exists: %s" % self.folder)

        if not self.__is_evictable:
            self.__log.info("Create .evictlock file in vault: %s" % self.folder)
            self.fileSystem.touch(self.nonevictablelock_filepath())

        if self.__is_sharded:
            self.__log.info("Create .sharded file in vault: %s" % self.folder)
            self.fileSystem.touch(self.sharded_filepath())

        self.__log.info("Create .lock file in vault: %s" % self.folder)
        self.fileSystem.touch(self.lock_filepath())

        return self.folder, self.metrics, self

    def create_time(self):
        try:
            folder_name = self.get_name()
            d = datetime.strptime(folder_name.split("_")[-1:][0], VAULT_NAME_FORMAT)
            return time.mktime(d.timetuple())
        except ValueError:
            self.__log.warning(
                "ValueError: folder name %s doesn't match the format %s" % (folder_name, VAULT_NAME_FORMAT))
        return time.time()

    def create_timestamp(self):
        return int(self.create_time() * 1000)

    def create_timestamp_sec(self):
        return int(self.create_time())

    def tail_console(self, num=5):
        return b" ".join(fsutil.tail(self.folder + "/.console", num))

    def __exit__(self, tpe, exception, tb):
        self.__log.info("Close vault")
        self.fileSystem.unlink(self.lock_filepath())

        exception_message = ""
        if exception:
            exception_message = "\n".join(format_exception(tpe, exception, tb))
        self.store_metrics(exception_message)

    def get_name(self):
        return self.fileSystem.basename(self.folder)

    def get_path(self):
        return self.folder

    def __repr__(self):
        return "Vault(%s)" % self.get_name()

    def __eq__(self, other):
        try:
            return self.__timestamp == other.__timestamp
        except:
            raise TypeError("unorderable types: %s == %s" % (type(self), type(other)))

    def __hash__(self):
        return hash(self.__timestamp)

    def __ne__(self, other):
        try:
            return self.__timestamp != other.__timestamp
        except:
            raise TypeError("unorderable types: %s != %s" % (type(self), type(other)))

    def __lt__(self, other):
        try:
            return self.__timestamp < other.__timestamp
        except:
            raise TypeError("unorderable types: %s < %s" % (type(self), type(other)))

    def to_json(self):
        return {
            "id": self.get_name(),
            "failed": self.is_failed(),
            "locked": self.is_locked(),
            "sharded": self.is_sharded(),
            "canceled": self.is_canceled(),
            "ts": self.create_timestamp(),
            "metrics": self.load_metrics()
        }