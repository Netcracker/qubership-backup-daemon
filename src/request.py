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

import logging
import jsonschema
import re
from werkzeug.utils import secure_filename

import configuration
import constants


safe_args = re.compile('[0-9a-z-_]', re.I)
log = logging.getLogger("RequestHandler")
allowed_api_keys = ["allow_eviction", "args", "dbs", "vault", "ts", "changeDbNames", "sharded", "externalBackupPath", "prefix", "storageName", "blobPath"]
allowed_extensions = ["zip", "tgz"]


class ApiException(Exception):
    def __init__(self, message, code):
        super(ApiException, self).__init__(message)
        self.code = code
        self.message = message


class RequestHelper:
    def __init__(self, request):
        self.__request = request
        self.__path = request.path
        self.__content = request.get_json()
        if self.__content is None:
            self.__content = {}
        if len(self.__content) > 0:
            log.info("Incoming JSON content: %s" % self.__content)

    def get_vault_name(self):
        content = self.__content
        if 'vault' in content:
            return content['vault']
        else:
            return None

    def get_ts(self):
        content = self.__content
        if 'ts' in content:
            return content['ts']
        else:
            return None

    def get_full_evict_policy(self):
        content = self.__content

        if 'fullEvictionPolicy' in content:
            return content['fullEvictionPolicy']
        else:
            raise ApiException('Sorry, wrong JSON string. No "fullEvictionPolicy" parameter found.', 400)

    def get_sharded(self):
        content = self.__content

        if 'sharded' in content:
            return content['sharded']
        else:
            return False

    def get_backup_path(self):
        content = self.__content

        if 'externalBackupPath' in content:
            return content['externalBackupPath']
        else:
            return None

    def get_backup_prefix(self):
        content = self.__content
        if 'prefix' in content:
            return content['prefix']
        return None

    def get_external(self):
        content = self.__content

        if 'external' in content:
            return content['external']
        else:
            return False

    def get_custom_vars(self):
        custom_variables = \
            {k: v for k, v in configuration.config.custom_vars.items() if v}
        content = self.__content

        if content:
            for key in content:
                if key not in allowed_api_keys:
                    if key in configuration.config.custom_vars:
                        custom_variables[key] = content[key]
                    else:
                        raise ApiException("Wrong json key transferred via API: '%s', allowed keys are: %s" % (
                            key, allowed_api_keys + list(configuration.config.custom_vars)), 500)

        return custom_variables

    def get_allow_eviction(self):
        if self.__content and "allow_eviction" in self.__content:
            return self.__content['allow_eviction'] in ['true', 'True', '1', 't', 'y', 'yes']
        else:
            return True

    @staticmethod
    def validate_dbs(dbs=None):
        if not dbs:
            return

        schema = {
            "anyOf": [
                {
                    "type": "string"
                },
                {
                    "type": "object",
                    "patternProperties": {
                        "[0-9a-zA-Z-_]": {
                            "type": "object",
                            "properties": {
                                "collections": {
                                    "type": "array",
                                    "items": {
                                        "anyOf": [
                                            {"type": "string"},
                                            {"type": "object", "maxProperties": 1}
                                        ]
                                    }
                                },
                                "tables": {
                                    "type": "array",
                                    "items": {
                                        "anyOf": [
                                            {"type": "string"}
                                        ]
                                    }
                                },
                            },
                            "additionalProperties": False,
                            "dependencies": {
                                "collections": {"not": {"required": ["tables"]}},
                                "tables": {"not": {"required": ["collections"]}}
                            }
                        }
                    }
                }
            ]
        }

        for item in dbs:
            try:
                jsonschema.validate(item, schema)
            except jsonschema.exceptions.ValidationError:
                raise ApiException("Wrong JSON database item: %s. Failing" % item, 500)

    @staticmethod
    def __check(it, num):
        # returns true if num elements of it are true
        it = iter(it)
        return all(any(it) for _ in range(num))

    def get_backup_dbs(self):
        content = self.__content

        if self.__check(["args" in content, "instances" in content, "dbs" in content], 2):
            # you should use 'instances', 'args' and 'dbs' are for backwards compatibility
            raise ApiException(
                "Sorry, you passed at least 2 of 'args', 'instances', 'dbs' parameters. Please pass only one of them",
                500)

        if "args" in content:
            content['dbs'] = content['args']

        if "instances" in content:
            content['dbs'] = content['instances']

        if "dbs" in content:
            for db in content['dbs']:
                try:
                    if not safe_args.match(db):
                        raise ApiException(
                            "Wrong database names transferred via API: '%s', names must match regex: [0-9a-zA-Z-_]"
                            % db, 500)
                except TypeError:
                    try:
                        if not safe_args.match(list(db.keys())[0]):
                            raise ApiException(
                                "Wrong database names transferred via API: '%s', names must match regex: [0-9a-zA-Z-_]"
                                % db, 500)
                    except Exception as e:
                        raise ApiException("Failed during DB names check on db: %s. Error: %s" % (db, str(e)),
                                           500)

                dbs = content['dbs']
                RequestHelper.validate_dbs(dbs)

                return dbs
        else:
            return None

    def get_restore_dbs(self):
        content = self.__content

        if "args" in content:
            content['dbs'] = content['args']

        if "dbs" in content:
            if not isinstance(content['dbs'], list):
                raise ApiException("dbs must be a list of databases", 400)

            for db in content['dbs']:
                try:
                    if not safe_args.match(db):
                        raise ApiException("Wrong db names transferred via API, names must match regex: [0-9a-zA-Z-_]", 500)
                except TypeError:
                    try:
                        if not safe_args.match(list(db.keys())[0]):
                            raise ApiException(
                                "Wrong database names transferred via API: '%s', names must match regex: [0-9a-zA-Z-_]"
                                % db, 500)
                    except Exception as e:
                        raise ApiException("Failed during DB names check on db: %s. Error: %s" % (db, str(e)),
                                           500)
            RequestHelper.validate_dbs(content["dbs"])
            dbs = tuple(content['dbs'])
        else:
            dbs = None

        return dbs

    def get_db_maps(self):
        content = self.__content

        if not content:
            return None

        if "changeDbNames" in content:
            for old, new in list(content['changeDbNames'].items()):
                if not safe_args.match(old):
                    raise ApiException("Wrong old db names transferred via changeDbNames API: %s,"
                                       " names must match regex: [0-9a-zA-Z-_]" % old,
                                       500)
                if not safe_args.match(new):
                    raise ApiException(
                        "Wrong new db names transferred via changeDbNames API: %s,"
                        " names must match regex: [0-9a-zA-Z-_]" % new,
                        500)
            db_map = content['changeDbNames']
        else:
            db_map = None

        return db_map

    def get_proc_type(self):
        if self.__path.find('incremental') != -1:
            return constants.INCREMENTAL
        else:
            return constants.FULL

    @staticmethod
    def _allowed_archive(filename):
        return '.' in filename and \
            filename.rsplit('.', 1)[1].lower() in allowed_extensions

    def get_uploaded_archive(self):
        if 'file' not in self.__request.files:
            raise ApiException("No file part", 400)

        file = self.__request.files['file']
        if not file or file.filename == '':
            raise ApiException("No selected file", 400)

        if not RequestHelper._allowed_archive(file.filename):
            raise ApiException("Wrong filename format: {}".format(file.filename), 400)

        return secure_filename(file.filename), file

    def get_backup_type(self):
        if 'type' in self.__request.values:
            return self.__request.values.get('type')
        else:
            return 'full'

    def get_allow_overwriting(self):
        if 'allow_overwriting' in self.__request.values:
            return self.__request.values.get('allow_overwriting') in ['true', 'True', '1', 't', 'y', 'yes']
        else:
            return False
