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

import json
import logging
import logging.handlers
import os
import shutil

from flask import Flask, request, Response, stream_with_context
from flask.wrappers import Request
from flask_httpauth import HTTPBasicAuth
from flask_restx import Resource, Api

import fsutil
from prometheus_metrics.layout_metrics import prometheus_metrics_from_json
from request import RequestHelper, ApiException
from datetime import datetime, timezone
import configuration


class IllegalStateException(Exception):
    def __init__(self, message):
        super(IllegalStateException, self).__init__(message)
        self.message = message


# Auth type definition for Swagger
swaggerAuth = {
    'apikey': {
        'type': 'basic',
    }
}

app = Flask("BackupHttpApi")
api = Api(app, version='1.0', title='BackupHttpApi', description='A backup-daemon HTTP API',
          doc='/swagger-ui', default_swagger_filename='/swagger-ui/swagger.json',
          authorizations=swaggerAuth)

log = logging.getLogger("werkzeug")


class HealthFilter(logging.Filter):
    def filter(self, record):
        message = record.getMessage()
        result = 'GET /health/prometheus HTTP/1.1' not in message
        return result


file_handler = logging.handlers.RotatingFileHandler('/var/log/api_requests.log', maxBytes=100000, backupCount=10)

log.addFilter(HealthFilter())
log.addHandler(file_handler)


backupExecutor = None
auth = HTTPBasicAuth()

def _rfc3339_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def _rfc3339_from_ts_ms(ts_ms: int) -> str:
    return datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc).isoformat().replace("+00:00", "Z")

def _map_job_status_to_v2(status: str) -> str:
    if status == "Successful":
        return "completed"
    if status == "Failed":
        return "failed"
    if status == "Processing":
       return "inProgress"
    return "notStarted"

def _mk_db_list(databases, db_status: str):
    return [{"databaseName": d, "status": db_status} for d in (databases or [])]


# Logic to separate APIS by groups/namespace in Swagger
# To useit need uncomment line below, change decorator from @api.xxx to @api_backup.xxx
#   api_backup = Namespace('backup/restore', description='Backup/Restore related operations')
# and add at the end of file the code:
#   api.add_namespace(api_backup)
# and add in imports:
#   from flask_restx import Resource, Api


@ auth.verify_password
def verify(username, password):
    if backupExecutor.login_required:
        if not (username and password):
            return False
        return (fsutil.readenv("BACKUP_DAEMON_API_CREDENTIALS_USERNAME") == username) \
            and (fsutil.readenv("BACKUP_DAEMON_API_CREDENTIALS_PASSWORD") == password)
    else:
        return True


# Apply WA from https://github.com/pallets/flask/issues/4552#issuecomment-1109785314
# WA can be rolled back after resolving the issue: https://github.com/python-restx/flask-restx/issues/422
class AnyJsonRequest(Request):  # Start WA
    def on_json_loading_failed(self, e):
        if e is not None:
            return super().on_json_loading_failed(e)


app.request_class = AnyJsonRequest  # End WA


@ api.route('/evict')
@ api.route('/incremental/evict')
@ api.route('/evict/<string:vault>')
@ api.route('/incremental/evict/<string:vault>')
@ api.doc(
    description = 'Start eviction process for full or incremental storage',
    params = {'vault': 'Backup ID'}
)
class Evict(Resource):
    @ auth.login_required
    @ api.doc(
        responses = {
            200: 'OK',
            500: 'Internal Server Error'
        }
    )
    def post(self, vault=None):
        req_helper = RequestHelper(request)
        proc_type = req_helper.get_proc_type()

        if not vault:
            backupExecutor.enqueue_eviction(proc_type)
            return "Ok"
        else:
            message, code = backupExecutor.remove_backup(vault, proc_type)
            log.debug("EVICT VAULT: %s, %s", message, code)
            return Response(json.dumps(message), status=code, mimetype="application/json")


@api.route('/health')
@api.route('/incremental/health')
@api.route('/health/<string:metrics_type>')
@api.route('/incremental/health/<string:metrics_type>')
@api.doc(
    description='Status of backup daemon and metrics for full or incremental storage',
    params={'metrics_type': 'The type of metrics. If omitted, it returns response in json format'}
)
class Health(Resource):

    @api.doc(
        responses={
            200: 'OK',
            500: 'Internal Server Error'
        }
    )
    def get(self, metrics_type=None):
        try:
            req_helper = RequestHelper(request)
            proc_type = req_helper.get_proc_type()
            processor = backupExecutor.get_processor(proc_type)

            vaults = processor.storage.list()
            vaults_size = len(vaults)

            log.debug(f"Vaults: {[vault.get_name() for vault in vaults]}")
            vaults.reverse()

            status = False  # False = "Warning", True = "UP"
            last = last_successful = None

            # calculate last successful
            for vault in vaults:
                if not vault.is_failed():
                    last_successful = vault.to_json()
                    status = True
                    break

            if vaults_size > 0:
                last_vault = vaults[:1][0]
                last = last_vault.to_json()
                if last_vault.is_failed():
                    status = False
            else:
                status = True

            status_string = "UP" if status else "Warning"

            if processor.s3_enabled:
                json_metrics = {
                    "status": status_string,
                    "storage": {
                        "dump_count": vaults_size,
                    }
                }
            else:
                fs_stats = processor.storage.fs_space()
                json_metrics = {
                    "status": status_string,
                    "storage": {
                        "dump_count": vaults_size,
                        "size": processor.storage.size(),
                        "free_space": fs_stats["free_space"],
                        "total_space": fs_stats["total_space"],
                        "free_inodes": fs_stats["free_inodes"],
                        "total_inodes": fs_stats["total_inodes"],
                        "used_inodes": fs_stats["total_inodes"] - fs_stats["free_inodes"]
                    }
                }

            if last_successful is not None:
                json_metrics["storage"]["lastSuccessful"] = last_successful

            if last is not None:
                json_metrics["storage"]["last"] = last

            json_metrics["backup_queue_size"] = processor.scheduler.queue_size()

            if metrics_type == 'prometheus':
                # now status metric in json have two version of value: "UP" and "Warning"
                # prometheus cannot work with string metric values
                json_metrics['status'] = 1.0 if json_metrics['status'] == 'UP' else 0.0
                return Response(response=prometheus_metrics_from_json(json_metrics), status=200)
            else:
                return json_metrics
        except ApiException as err:
            return Response(response=err.message, status=err.code)
        except Exception as err:
            return Response(response=str(err), status=500)


@api.route('/backup')
@api.route('/incremental/backup')
@api.doc(
    description='Run full manual or incremental backup. Returns backup folder (vault)'
)
class Backup(Resource):
    @staticmethod
    def __check(it, num):
        # returns true if num elements of it are true
        it = iter(it)
        return all(any(it) for _ in range(num))

    @auth.login_required
    @api.doc(
        responses={
            200: 'OK',
            409: 'Conflict',
            500: 'Internal Server Error'
        }
    )
    def post(self):
        req_helper = RequestHelper(request)

        custom_variables = req_helper.get_custom_vars()
        allow_eviction = req_helper.get_allow_eviction()
        dbs = req_helper.get_backup_dbs()
        proc_type = req_helper.get_proc_type()
        sharded = req_helper.get_sharded()
        backup_path = req_helper.get_backup_path()
        backup_prefix = req_helper.get_backup_prefix()

        try:
            backup_id = backupExecutor.enqueue_backup("http call", custom_variables, allow_eviction,
                                                      dbs, proc_type, sharded, backup_path, backup_prefix)
            return Response(backup_id, mimetype="application/json")
        except IllegalStateException as ise:
            error_msg = "Error during backup process: %s" % ise.message
            log.error(error_msg)
            return Response(json.dumps(
                {
                    "status": "Failed",
                    "message": error_msg
                }),
                mimetype="application/json",
                status=409)


@api.route('/restore')
@api.route('/incremental/restore')
@api.doc(
    description='Run recovery of data from full or incremental backup'
)
class Restore(Resource):
    @auth.login_required
    @api.doc(
        responses={
            200: 'OK',
            404: 'Not Found',
            500: 'Internal Server Error'
        }
    )
    def post(self):
        req_helper = RequestHelper(request)
        custom_variables = req_helper.get_custom_vars()
        proc_type = req_helper.get_proc_type()

        try:
            backup_path = req_helper.get_backup_path()
            vault_name = req_helper.get_vault_name()
            ts = req_helper.get_ts()
            if vault_name is None and ts is None:
                raise ApiException('Sorry, wrong JSON string. No "vault" or "ts" parameter. '
                                   'Try something like: {"vault":"/backup-storage/20170913T1114", "dbs":["db1","db2"]}',
                                   404)
            dbs = req_helper.get_restore_dbs()
            db_map = req_helper.get_db_maps()
            message, code = backupExecutor.get_backup_stats(
                vault_name, proc_type, ts, backup_path)
            if code == 404:
                raise ApiException("Restore failed. Wrong vault name '%s' or ts '%s' supplied: . No such backup" %
                                   (vault_name, ts), 404)
            name = message['id']
        except TypeError as e:
            log.warning("Http call: Recovery failed. Wrong JSON string")
            log.warning(str(e))
            return Response(json.dumps(
                {
                    "status": "Failed",
                    "message": 'Sorry, wrong JSON string. Try something like: '
                               '{"vault":"/backup-storage/20170913T1114", '
                               '"dbs":["db1","db2"]}, "changeDbNames": '
                               '{"old_name1":"new_name1", "old_name2": "new_name2"}'
                }),
                mimetype="application/json",
                status=500)
        except ApiException as e:
            log.error(e.message)
            return Response(json.dumps({"status": "Failed", "message": e.message}), mimetype="application/json",
                            status=e.code)

        task_id = backupExecutor.enqueue_restore(
            "http call", name, dbs, db_map, custom_variables, proc_type, backup_path)
        return Response(task_id, mimetype="application/json")


@api.route('/external/restore')
@api.doc(
    description='Run external restore of managed storage'
)
class ExternalRestoreRequest(Resource):
    def __init__(self, storage):
        self.__log = logging.getLogger("ExternalRestoreEndpoint")

    @auth.login_required
    @api.doc(
        responses={
            200: 'OK',
            500: 'Internal Server Error'
        }
    )
    def post(self):
        self.__log.debug("Endpoint /external/restore has been called")
        req_helper = RequestHelper(request)
        custom_variables = req_helper.get_custom_vars()
        task_id = backupExecutor.enqueue_restore(
            "http call", "", None, "", custom_variables=custom_variables)
        return Response(task_id, mimetype="application/json")


@api.route('/jobstatus/<string:task_id>')
@api.route('/incremental/jobstatus/<string:task_id>')
@api.doc(
    description='Backup or recovery status',
    params={'task_id': 'ID of the task'}
)
class JobStatus(Resource):
    @auth.login_required
    @api.doc(
        responses={
            200: 'OK',
            500: 'Internal Server Error'
        }
    )
    def get(self, task_id):
        try:
            req_helper = RequestHelper(request)
            proc_type = req_helper.get_proc_type()

            message, code = backupExecutor.get_job_status(task_id, proc_type)
            log.debug("JOB STATUS: %s, %s" % (message, code))

            return Response(
                json.dumps({k: v.decode("utf-8") if isinstance(v,
                           bytes) else v for k, v in message.items()}),
                status=code,
                mimetype="application/json")
        except Exception as ex:
            message = {
                "message": "Sorry, no job '%s' recorded in database" % "task_id"}
            log.info("Error in JobStatus api  " + str(ex))
            return Response(json.dumps(message), status=500, mimetype="application/json")


@api.route('/listbackups')
@api.route('/incremental/listbackups')
@api.route('/listbackups/<string:vault>')
@api.route('/incremental/listbackups/<string:vault>')
@api.doc(
    description='Backup list names or particular backup information',
    params={'vault': 'Backup ID'}
)
class ListBackups(Resource):
    @auth.login_required
    @api.doc(
        responses={
            200: 'OK',
            500: 'Internal Server Error'
        }
    )
    def get(self, vault=None):
        req_helper = RequestHelper(request)
        proc_type = req_helper.get_proc_type()
        processor = backupExecutor.get_processor(proc_type)

        if vault:
            message, code = backupExecutor.get_backup_stats(vault, proc_type)
            return Response(json.dumps(message), mimetype="application/json", status=code)
        else:
            return Response(json.dumps(processor.storage.list(timestamps_only=True)),
                            mimetype="application/json", status=200)


@api.route('/find')
@api.route('/incremental/find')
@api.doc(
    description='Find the backup with timestamp equal or newer than specified'
)
class Find(Resource):
    @auth.login_required
    @api.doc(
        responses={
            200: 'OK',
            404: 'Not Found'
        }
    )
    def get(self):
        req_helper = RequestHelper(request)
        proc_type = req_helper.get_proc_type()
        ts = req_helper.get_ts()
        if ts is None:
            raise ApiException('Sorry, wrong JSON string. No "ts" parameter.',
                               404)
        message, code = backupExecutor.get_backup_stats(
            ts=ts, proc_type=proc_type)
        return Response(json.dumps(message), mimetype="application/json", status=code)


@api.route('/evictionpolicy')
@api.route('/incremental/evictionpolicy')
@api.doc(
    description='Update eviction policy in runtime'
)
class EvictionPolicy(Resource):
    @auth.login_required
    @api.doc(
        responses={
            200: 'OK'
        }
    )
    def post(self):
        req_helper = RequestHelper(request)
        proc_type = req_helper.get_proc_type()

        full_evict_policy = req_helper.get_full_evict_policy()

        backupExecutor.update_eviction_policy(full_evict_policy, proc_type)
        return 'Ok'


@api.route('/backup/s3/<string:backup_id>')
@api.doc(
    description='Generate a pre-signed URL to share an S3 object',
    params={'backup_id': 'Backup ID'}
)
class S3PresignedURL(Resource):
    """
    Returns presigned URL (access without credentials)
    example of request:
        curl -XGET -u backup:backup -v localhost:8080/backup/s3/20210601T115105?expiration=2000
    """

    @auth.login_required
    @api.doc(
        responses={
            200: 'OK',
            204: 'No Content'
        }
    )
    def get(self, backup_id):
        req_helper = RequestHelper(request)
        proc_type = req_helper.get_proc_type()
        processor = backupExecutor.get_processor(proc_type)
        if not processor.s3_enabled:
            return Response("S3 storage is disabled", status=204)
        vault = processor.storage.get_vault(backup_id)
        if vault is None:
            return Response("Backup not found", status=204)
        extensions = ('.zip', '.tar', '.gz')
        files = processor.s3Client.list_files(vault.folder)
        urls = [processor.s3Client.create_presigned_url(file, request.args.get(
            'expiration')) for file in files if file.endswith(extensions)]
        return json.dumps(urls)


@api.route('/backup/<string:backup_id>')
@api.route('/incremental/backup/<string:backup_id>')
@api.doc(
    description='Download backup archive. Does not work with S3',
    params={'backup_id': 'Backup ID'}
)
class Download(Resource):
    """
    Does not work with S3
    """

    @auth.login_required
    @api.doc(
        responses={
            200: 'OK',
            204: 'No Content'
        }
    )
    def get(self, backup_id):
        req_helper = RequestHelper(request)
        proc_type = req_helper.get_proc_type()
        processor = backupExecutor.get_processor(proc_type)

        def generate(archive_file):
            stream = processor.storage.prot_get_as_stream(
                backup_id, archive_file)
            with stream as f:
                chunk_size = 4096
                while True:
                    data = f.read(chunk_size)
                    if len(data) == 0:
                        f.close()
                        shutil.rmtree(f'{directory}_tmp')
                        return
                    yield data

        vault = processor.storage.get_vault(backup_id)
        directory = vault.folder if vault else None
        if directory:
            os.makedirs(f'{directory}_tmp')
            file = shutil.make_archive(
                f'{directory}_tmp/{backup_id}', 'zip', directory)
            file_stream = generate(file)
            log.info("Returning response for file: %s" % file)
            return Response(stream_with_context(
                file_stream),
                mimetype='application/zip',
                headers=[
                    ('Content-Type', 'application/zip'),
                    ('Content-Disposition', file)
            ])
        return Response(
            "Cannot find backup with id {} ".format(backup_id),
            status=204)


@api.route('/restore/backup')
@api.doc(
    description='Upload backup archive. Does not work with S3'
)
class Upload(Resource):
    """
    Does not work with S3
    """

    @auth.login_required
    @api.doc(
        responses={
            200: 'OK',
            500: 'Internal Server Error'
        }
    )
    def post(self):
        req_helper = RequestHelper(request)
        type = req_helper.get_backup_type()
        allow_overwriting = req_helper.get_allow_overwriting()
        allowed_types = ['granular', 'full']
        try:
            if type not in allowed_types:
                raise ApiException(
                    'Sorry, wrong backup type. Type should be granular or full', 500)
            file_name, file = req_helper.get_uploaded_archive()
            log.info("file name: %s" % file_name)

            tmp_archive_name = os.path.join('/tmp', file_name)
            file.save(tmp_archive_name)

            processor = backupExecutor.backup_processor
            granular_vault_path = os.path.join(
                processor.storage.root, 'granular', os.path.splitext(file_name)[0])
            full_vault_path = os.path.join(
                processor.storage.root, '', os.path.splitext(file_name)[0])
            if os.path.exists(granular_vault_path) and type == 'full':
                raise ApiException(
                    'Sorry, backup with the same name exists as granular backup.', 500)
            if os.path.exists(full_vault_path) and type == 'granular':
                raise ApiException(
                    'Sorry, backup with the same name exists as full backup.', 500)
            if type == 'full':
                vault_path = full_vault_path
            else:
                vault_path = granular_vault_path
            if not os.path.exists(vault_path):
                os.mkdir(vault_path)
            else:
                if allow_overwriting:
                    shutil.rmtree(vault_path)
                    os.mkdir(vault_path)
                else:
                    raise ApiException(
                        'Sorry, backup is already exists and allow_overwriting is False.', 500)

            shutil.unpack_archive(tmp_archive_name, vault_path)
            log.info("Unzip path: %s" % vault_path)
            os.remove(tmp_archive_name)
            return Response(status=200)
        except ApiException as err:
            return Response(response=err.message, status=err.code)


@api.route('/terminate/<string:backup_id>')
@api.doc(
    description='Terminate running backup procedure',
    params={'backup_id': 'Backup ID'}
)
class Terminate(Resource):

    @api.doc(
        responses={
            200: 'OK',
            404: 'Not Found',
            406: 'Not Acceptable',
            500: 'Internal Server Error'
        }
    )
    def post(self, backup_id):
        req_helper = RequestHelper(request)
        proc_type = req_helper.get_proc_type()
        backup_path = req_helper.get_backup_path()
        try:
            result, code = backupExecutor.get_backup_stats(
                backup_id, proc_type, backup_path)
            if code == 404:
                raise ApiException("Cancel failed. Wrong vault name supplied: '%s'. No such backup" % backup_id,
                                   404)
            if not result["locked"]:
                return Response(json.dumps(
                    {
                        "status": "Failed",
                        "message": 'Provided backup id is not locked, maybe has already been completed. '
                                   f'Please check backup {backup_id} status.'
                    }),
                    mimetype="application/json",
                    status=406)
        except TypeError:
            log.warning("Http call: Recovery failed. Wrong JSON string")
            return Response(json.dumps(
                {
                    "status": "Failed",
                    "message": 'Sorry, wrong JSON string. Try something like: '
                               '{"vault":"/backup-storage/20170913T1114", '
                }),
                mimetype="application/json",
                status=500)
        except ApiException as e:
            log.error(e.message)
            return Response(json.dumps({"status": "Failed", "message": e.message}), mimetype="application/json",
                            status=e.code)
        log.info(f'Backup path {backup_path}, backup_id {backup_id}')
        message, code = backupExecutor.terminate_backup(backup_id, backup_path)
        log.debug("TERMINATE BACKUP: %s, %s", message, code)
        return Response(json.dumps(message), status=code, mimetype="application/json")


@api.route('/api/v2/backup')
class BackupV2(Resource):
    @auth.login_required
    @api.doc(responses={200: "OK", 400: "Bad Request", 500: "Internal Server Error"})
    def post(self):
        payload = request.get_json(silent=True) or {}

        storage_name = payload.get("storageName", "")
        blob_path = payload.get("blobPath")
        databases = payload.get("databases", [])

        if not blob_path or not isinstance(blob_path, str):
            return Response(response="blobPath must be a non-empty string", status=400)
        if not isinstance(databases, list) or any(not isinstance(x, str) for x in databases):
            return Response(response="databases must be a list of strings", status=400)

        custom_variables = {k: v for k, v in configuration.config.custom_vars.items() if v}
        custom_variables["storageName"] = storage_name
        custom_variables["prefix"] = blob_path

        proc_type = RequestHelper(request).get_proc_type()

        backup_id = backupExecutor.enqueue_backup(
            reason="http v2",
            custom_variables=custom_variables,
            allow_eviction=True,
            dbs=databases,
            proc_type=proc_type,
            sharded=False,
            backup_path=None,
            backup_prefix=blob_path,
        )

        resp = {
            "status": "notStarted",
            "backupId": backup_id,
            "creationTime": _rfc3339_now(),
            "storageName": storage_name,
            "blobPath": blob_path,
            "databases": _mk_db_list(databases, "notStarted"),
        }
        return Response(response=json.dumps(resp), status=200, mimetype="application/json")


@api.route('/api/v2/backup/<string:backup_id>')
@api.doc(description="Adapter-style API. Requires ?blobPath=<path> to locate backup.")
class BackupV2Status(Resource):
    @auth.login_required
    @api.doc(responses={200: "OK", 400: "Bad Request", 404: "Not Found", 500: "Internal Server Error"})
    def get(self, backup_id: str):
        blob_path = request.args.get("blobPath")
        if not blob_path:
            return Response(response="blobPath query param is required", status=400)

        proc_type = RequestHelper(request).get_proc_type()

        job_msg, job_code = backupExecutor.get_job_status(backup_id, proc_type)
        if job_code == 404:
            return Response(response=json.dumps(job_msg), status=404, mimetype="application/json")

        overall = _map_job_status_to_v2(job_msg.get("status"))


        creation_time = _rfc3339_now()
        dbs = []
        stats, stats_code = backupExecutor.get_backup_stats(backup_id, proc_type, None, blob_path)
        if stats_code == 200 and isinstance(stats, dict):
            try:
                creation_time = _rfc3339_from_ts_ms(int(stats.get("ts")))
            except Exception:
                pass
            try:
                processor = backupExecutor.get_processor(proc_type)
                dbs = processor._BackupProcessor__get_backup_dbs(backup_id, vault_path=blob_path)
            except Exception:
                dbs = []

        resp = {
            "status": overall,
            "backupId": backup_id,
            "creationTime": creation_time,
            "storageName": "",
            "blobPath": blob_path,
            "databases": _mk_db_list(dbs, overall),
        }
        return Response(response=json.dumps(resp), status=200, mimetype="application/json")