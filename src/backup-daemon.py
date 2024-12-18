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

import os
import logging
import signal
import sys
import subprocess
from subprocess import check_output
import json

from pyhocon import ConfigFactory, ConfigTree
from datetime import datetime
import time

import db
import eviction
import scheduler
import storage
import fsutil
import httpapi
import configuration
from constants import *


class BackupProcessException(Exception):
    pass


class BackupProcessor:

    def __init__(self, proc_config, proc_type):
        self.proc_type = proc_type
        self.s3_enabled = False
        if self.proc_type == INCREMENTAL:
            if proc_config['incremental_enabled'] == "false":
                return

        if 's3_enabled' in proc_config and proc_config['s3_enabled'].lower() == "true":
            # ssl_verify might be False, True or path to certs
            if proc_config['s3_ssl_verify'].lower() == "true":
                if backup_cfg["s3_certs_path"] == "":
                    ssl_verify = True
                else:
                    ssl_verify = f'{os.environ.get("S3_CERT_PATH_INTERNAL")}/ca.crt'
            elif proc_config['s3_ssl_verify'].lower() == "false":
                ssl_verify = False
            else:
                ssl_verify = proc_config['s3_ssl_verify']
            self.s3Client = storage.S3Client(proc_config['s3_url'], proc_config['s3_bucket'], proc_config['s3_key_id'],
                                             proc_config['s3_key_secret'], ssl_verify)
            self.storage = storage.Storage(proc_config['storage_root'], proc_config['external_storage_root'],
                                           file_system=storage.S3FileSystem(self.s3Client))
            self.s3_enabled = True
        else:
            self.storage = storage.Storage(
                proc_config['storage_root'], proc_config['external_storage_root'])

        self.external_storage = proc_config['external_storage_root']
        self.db = db.DB(self.storage.root + "/backup.sqlite")
        self.backup_cmd = proc_config['backup_cmd']
        self.restore_cmd = proc_config['restore_cmd']
        self.evict_cmd = proc_config['evict_cmd']
        self.db_list_cmd = proc_config['db_list_cmd']
        self.termination_cmd = proc_config['termination_cmd']
        self.full_eviction_policy = proc_config['eviction_policy']
        self.granular_eviction_policy = proc_config['granular_eviction_policy']
        self.scheduler = scheduler.Scheduler(
            proc_config['schedule'], self.__do_process, self.__do_anyway)
        if proc_config['granular_schedule'] and len(proc_config["scheduled_dbs"]) > 0:
            granular_scheduler = scheduler.Scheduler(
                proc_config['granular_schedule'], self.__do_process, self.__do_anyway, dbs=proc_config['scheduled_dbs'])
            granular_scheduler.start()

        self.scheduler.start()
        # http_login required or not
        self.login_required = False

    def get_backup_action(self):
        if self.proc_type == INCREMENTAL:
            return INCREMENTAL_BACKUP
        else:
            return COMMON_BACKUP

    def get_restore_action(self):
        if self.proc_type == INCREMENTAL:
            return INCREMENTAL_RESTORE
        else:
            return COMMON_RESTORE

    def get_pid(self, cmd):
        try:
            return int(check_output(["pidof", "-s", cmd.split()[0]]))
        except Exception as e:
            log.error(f'Cant find pid for command {cmd.split()[0]}')
            return 0

    def terminate_process_by_pid(self, pid):
        try:
            log.info(f'Terminate command will be sent to pid {pid}')
            os.kill(pid, signal.SIGTERM)
            log.info(f'Terminate command was sent to pid {pid}')
        except Exception as e:
            log.error(f"Can't terminate pid {pid}, {e}")

    def enqueue_backup(self, reason, custom_variables, allow_eviction=True, dbs=None, sharded=False, backup_path=None):
        if dbs:
            is_granular = True
        else:
            is_granular = False
        action = self.get_backup_action()
        if backup_path is None:
            vault = self.storage.open_vault(vault_name=backup_path, allow_eviction=allow_eviction,
                                            is_granular=is_granular,
                                            is_sharded=sharded, is_external=False)
        else:
            vault = self.storage.open_vault(allow_eviction=allow_eviction,
                                            is_granular=False,
                                            is_sharded=sharded, is_external=True, vault_path=backup_path)
        vault_name = vault.get_name()
        backup_id = vault.get_name()

        self.db.update_job(backup_id, action, "Queued", None, None)
        self.scheduler.enqueue_execution(reason=reason, action=action, allow_eviction=allow_eviction,
                                         dbs=dbs, vault_name=vault_name, task_id=backup_id,
                                         custom_variables=custom_variables, sharded=sharded,
                                         external=backup_path is not None, vault_path=backup_path)
        # sleep for 2 secs to prevent conflicts in DB
        time.sleep(2)
        return backup_id

    def enqueue_restore(self, reason, vault_name, dbs, dbmap, custom_variables, backup_path=None):
        action = self.get_restore_action()
        task_id = self.scheduler.generate_task_id()
        self.db.update_job(task_id, action, "Queued", None, None)
        self.scheduler.enqueue_execution(reason=reason, action=action,
                                         vault_name=vault_name, dbs=dbs,
                                         dbmap=dbmap, task_id=task_id,
                                         custom_variables=custom_variables,
                                         external=backup_path is not None, vault_path=backup_path)
        # sleep for 2 secs to prevent conflicts in DB
        time.sleep(2)
        return task_id

    def perform_evictions(self):
        log.info("Start full eviction process by policy: %s" %
                 self.full_eviction_policy)
        obsolete_full_vaults = eviction.evict(self.storage.list(type="full"),
                                              self.full_eviction_policy,
                                              accessor=lambda x: x.create_time(),
                                              exclude=self.storage.get_nonevictable_vaults())
        log.info("Start granular eviction process by policy: %s" %
                 self.granular_eviction_policy)
        obsolete_granular_vaults = eviction.evict(self.storage.list(type="granular"),
                                                  self.granular_eviction_policy,
                                                  accessor=lambda x: x.create_time(),
                                                  exclude=self.storage.get_nonevictable_vaults())
        log.info('Deleting full vaults: %s' % obsolete_full_vaults)
        log.info('Deleting granular vaults: %s' % obsolete_granular_vaults)
        obsolete_vaults = obsolete_full_vaults + obsolete_granular_vaults
        if len(obsolete_vaults) > 0:
            for vault in obsolete_vaults:
                self.storage.evict(vault)
                self.db.rm_vault_from_base(vault.get_name(), login=True)
                if self.evict_cmd:
                    self.execute_evict_cmd(vault)
        else:
            log.info("No obsolete vaults to evict")

    @staticmethod
    def trim_storage_from_vault(vault_folder):
        return vault_folder.split('/')[-1]

    @staticmethod
    def exec_error_msg(cmd, code):
        return "Execution of '%s' was finished with non zero exit code: %d" % (cmd, code)

    def get_backup_stats(self, vault_name=None, ts=None, backup_path=None):
        result = {}
        _storage = self.storage
        name = vault_name
        type = 'all'
        if backup_path is not None:
            type = 'full'
        if name is not None:
            if name not in _storage.list(timestamps_only=True, type=type, storage_path=backup_path):
                return "backup %s not found" % name, 404
        else:
            if ts is not None:
                name = _storage.find_by_ts(ts)
                if name is None:
                    return "backup with ts %s or newer not found" % ts, 404
            else:
                return "backup name or ts not found", 404
        vault_obj = _storage.get_vault(
            name, external=backup_path is not None, vault_path=backup_path)
        result['is_granular'] = vault_obj.is_granular()
        if vault_obj.is_granular():
            db_list = self.__get_backup_dbs(
                name, vault_path=backup_path)
        else:
            db_list = "%s backup" % self.proc_type

        log.debug("db_list: %s" % db_list)

        result['db_list'] = db_list
        result.update(vault_obj.to_json())
        result.update(result.pop('metrics'))
        try:
            result['size'] = str(result['size']) + 'b'
        except:
            result['size'] = 'Unknown'

        try:
            result['spent_time'] = str(result['spent_time']) + 'ms'
        except:
            result['spent_time'] = 'Unknown'

        try:
            if not result['failed'] and not result['locked'] and result['exit_code'] == 0:
                result['valid'] = True
            else:
                result['valid'] = False
        except:
            result['valid'] = False
        result['evictable'] = not vault_obj.is_nonevictable()

        if vault_obj.has_custom_vars():
            result['custom_vars'] = vault_obj.load_custom_variables()
        log.debug("Backup stats for backup: %s: %s" % (name, result))
        return result, 200

    def get_job_status(self, task_id):
        result = self.db.select_everything(task_id)

        if len(result) > 0:
            if result[0]['status'] == "Successful":
                code = 200
            elif result[0]['status'] == "Failed":
                code = 500
            else:
                code = 206
            message = result[0]
        else:
            code = 404
            message = {
                "message": "Sorry, no job '%s' recorded in database" % task_id}

        return message, code

    def __get_backup_dbs(self, vault_name, vault_path=None):
        log.debug("Getting dbs backed inside vault \"%s\"" % vault_name)
        vault_obj = self.storage.get_vault(
            vault_name, external=vault_path is not None, vault_path=vault_path)
        if not vault_obj:
            raise BackupProcessException("No such vault: %s" % vault_name)
        cmd_processed = self.__process_cmd(self.db_list_cmd, vault_obj.folder)
        proc = subprocess.Popen(
            cmd_processed, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out = list(map(lambda x: x.decode() if isinstance(
            x, bytes) else x, proc.stdout.read().splitlines()))
        return [x for x in out if x.rstrip()]

    def __perform_backup(self, task_id, allow_eviction, dbs, custom_variables, sharded=False, external=False,
                         vault_name=None, vault_path=None):
        if dbs and not external:
            is_granular = True
        else:
            is_granular = False

        action = self.get_backup_action()

        if vault_name in (None, ''):
            vault_name = task_id

        with self.storage.open_vault(vault_name=vault_name, allow_eviction=allow_eviction,
                                     is_granular=is_granular, is_sharded=sharded, is_external=external,
                                     vault_path=vault_path) as (vault_folder, metrics, vault_object):
            if vault_object:
                log.info("Start %s process to: %s" % (action, vault_folder))
                self.db.update_job(task_id, action, "Processing", self.trim_storage_from_vault(vault_folder),
                                   None, login=True)
                cmd_processed = self.__process_cmd(self.backup_cmd, vault_object.folder, dbs,
                                                   custom_variables=custom_variables)

                log_filepath = vault_folder + "/.console"
                exit_code = 0
                with open(log_filepath, "w") as log_file:
                    log.info("Execution logfile: %s" % log_filepath)
                    exit_code = subprocess.call(
                        cmd_processed, stdout=log_file, stderr=log_file)

                if configuration.config.logs_to_stdout:
                    with open(log_filepath, "r") as log_file:
                        print(log_file.read())

                metrics["exit_code"] = exit_code
                if custom_variables and configuration.config.publish_custom_vars:
                    vault_object.store_custom_variables(custom_variables)
                if self.storage.s3_enabled:
                    vault_object.store_metrics()
                    self.s3Client.upload_folder(vault_folder)
                if exit_code != 0:
                    msg = BackupProcessor.exec_error_msg(
                        cmd_processed, exit_code)
                    log.error(msg)
                    line_number = 5
                    tail = vault_object.tail_console(line_number)
                    msg = "Last %s lines of logfile: %s" % (
                        line_number, tail)
                    self.db.update_job(task_id, action, "Failed", self.trim_storage_from_vault(vault_folder),
                                       tail, login=True)
                    raise BackupProcessException(msg)
                else:
                    log.info("%s process successfully finished" % action)
                    self.db.update_job(task_id, action, "Successful", self.trim_storage_from_vault(vault_folder),
                                       None, login=True)

            else:
                log.error("%s process failed" % action)
                self.db.update_job(task_id, action, "Failed", None, "Can not create directory for a vault",
                                   login=True)
        # clean local buffer storage
        if self.storage.s3_enabled:
            fsutil.rmtree(vault_object.folder)

    def __perform_restore(self, task_id, vault_folder, custom_variables, dbs=None, dbmap=None, external=False,
                          vault_path=None):
        action = self.get_restore_action()
        vault_object = self.storage.get_vault(
            vault_folder, external, vault_path)
        log.info("Starting %s process from: %s, vault obj: %s, %s"
                 % (action, vault_folder, vault_object, vault_object.get_path()))

        if self.storage.s3_enabled:
            self.s3Client.download_folder(vault_object.folder)

        if dbs is not None:
            backed_dbs = self.__get_backup_dbs(vault_folder, vault_path)
            log.debug("Backed databases from %s: %s" %
                      (vault_folder, backed_dbs))

            wrong_dbs = [x if isinstance(x, str) else list(x.keys())[0] for x in dbs if ((isinstance(
                x, str) and x not in backed_dbs) or (isinstance(x, dict) and list(x.keys())[0] not in backed_dbs))]
            if len(wrong_dbs):
                msg = "Sorry, but databases %s don't exist in backup %s" % (
                    wrong_dbs, vault_folder)
                log.error(msg)
                self.db.update_job(task_id, action, "Failed", self.trim_storage_from_vault(vault_folder), msg,
                                   login=True)
                return
            if dbmap:
                for old, new in list(dbmap.items()):
                    if old not in backed_dbs:
                        error_message = "Sorry, but database name %s from dbmap doesn't exist in backup. Failing..." \
                                        % old
                        log.error(error_message)
                        self.db.update_job(task_id, action, "Failed", self.trim_storage_from_vault(vault_folder),
                                           error_message, login=True)
                        return

                log.info("Using dbmap: %s" % json.dumps(dbmap))

        else:
            if not configuration.config.enable_full_restore and not dbs:
                error_message = \
                    "Sorry, but vault %s contains full backup of database, you can't restore it fully via REST API" \
                    % self.trim_storage_from_vault(vault_folder)
                log.error(error_message)
                self.db.update_job(task_id, action, "Failed", self.trim_storage_from_vault(vault_folder),
                                   error_message, login=True)
                return

        self.db.update_job(task_id, action, "Processing", self.trim_storage_from_vault(
            vault_folder), None, login=True)

        cmd_processed = self.__process_cmd(self.restore_cmd, vault_object.folder, dbs, dbmap,
                                           custom_variables=custom_variables)
        if external:
            log_filepath = vault_object.folder + \
                "/restore_" + str(task_id) + ".log"
        else:
            log_filepath = self.storage.restore_logs_folder + \
                "/" + str(task_id) + ".log"
        exit_code = 0
        with open(log_filepath, "w") as log_file:
            log.info("Execution logfile: %s" % log_filepath)
            exit_code = subprocess.call(
                cmd_processed, stdout=log_file, stderr=log_file)
        if configuration.config.logs_to_stdout:
            with open(log_filepath, "r") as log_file:
                print(log_file.read())
        if exit_code != 0:
            msg = BackupProcessor.exec_error_msg(cmd_processed, exit_code)
            log.error(msg)
            line_number = 5
            tail = b"\n".join(fsutil.tail(log_filepath, line_number))
            msg = "Last %s lines of logfile: %s" % (line_number, tail)
            self.db.update_job(task_id, action, "Failed", self.trim_storage_from_vault(vault_folder),
                               tail, login=True)
            raise BackupProcessException(msg)
        else:
            log.info("%s process successfully finished" % action)
            self.db.update_job(task_id, action, "Successful", self.trim_storage_from_vault(vault_folder),
                               None, login=True)

        # clean local buffer storage
        if self.storage.s3_enabled:
            fsutil.rmtree(vault_object.folder)

    def remove_backup(self, vault_name):
        log.info("Trying to remove backup %s", vault_name)

        if vault_name not in self.storage.list(timestamps_only=True):
            msg = "backup %s not found" % vault_name
            log.warning(msg)
            return msg, 404
        else:
            vault_object = self.storage.get_vault(vault_name)
            if vault_object:
                if vault_object.is_locked():
                    msg = "Backup %s is locked and can't be removed" % vault_name
                    log.warning(msg)
                    return msg, 500
                else:
                    log.debug(
                        "Vault %s is found and is going to be deleted...", vault_name)
                    self.storage.evict(vault_object)
                    if self.vault_was_evicted(vault_name):
                        msg = "Backup %s successfully removed" % vault_name
                        log.info(msg)
                        if self.evict_cmd:
                            self.execute_evict_cmd(vault_object)
                        return msg, 200
                    else:
                        msg = "Backup %s failed to be removed" % vault_name
                        log.warning(msg)
                        return msg, 500

    def vault_was_evicted(self, vault_name):
        if self.storage.get_fs_type() == "s3":
            for x in range(5):
                if not self.storage.get_vault(vault_name):
                    return True
                else:
                    log.info(f"Waiting for {vault_name} deletion...")
                    time.sleep(1)
            return False
        return not self.storage.get_vault(vault_name)

    def terminate_backup(self, vault_folder, backup_path):
        log.info(f"Trying to terminate backup {vault_folder}")
        if vault_folder not in self.storage.list(timestamps_only=True, storage_path=backup_path, type='full'):
            msg = f"backup {vault_folder} not found"
            log.warning(msg)
            return msg, 404
        pid = self.get_pid(self.backup_cmd)
        if not pid:
            msg = "Nothing to terminate. No active backup procedure"
            log.info(msg)
            return msg, 404
        self.terminate_process_by_pid(pid)
        vault_object = self.storage.get_vault(
            vault_folder, vault_path=backup_path, external=backup_path is not None,)
        if vault_object:
            log.debug(
                f'Vault {vault_folder} is found and is going to be terminated...')
            action = self.get_backup_action()
            msg = f"Backup {vault_folder} successfully terminated"
            if self.termination_cmd:
                self.execute_termination_cmd(vault_object)
                log.info(f"Update status in database {vault_folder} {action}")
            else:
                log.info(
                    "Termination command was not provided. Only initial backup process was killed")
            fsutil.touch(vault_object.canceled_filepath())
            self.db.update_job(vault_folder, action, "Canceled", self.trim_storage_from_vault(vault_folder),
                               None, login=True)
            return msg, 200

    def execute_evict_cmd(self, vault_object):
        cmd_processed = self.__process_cmd(self.evict_cmd, vault_object.folder)
        exit_code = subprocess.call(cmd_processed)
        if exit_code != 0:
            msg = BackupProcessor.exec_error_msg(cmd_processed, exit_code)
            log.error(msg)
        else:
            log.info("Custom eviction process successfully finished")

    def execute_termination_cmd(self, vault_object):
        cmd_processed = self.__process_cmd(
            self.termination_cmd, vault_object.folder)
        exit_code = subprocess.call(cmd_processed)
        if exit_code != 0:
            msg = BackupProcessor.exec_error_msg(cmd_processed, exit_code)
            log.error(msg)
        else:
            log.info("Terminate action process successfully finished")

    @staticmethod
    def __split_command_line(cmd_line):
        import shlex
        lex = shlex.shlex(cmd_line)
        lex.quotes = '"'
        lex.whitespace_split = True
        lex.commenters = ''
        return list(lex)

    def __process_cmd(self, cmd, vault_folder, dbs=None, dbmap=None, custom_variables=None):
        log.debug("Processing: %s, %s, %s, %s, %s" %
                  (cmd, vault_folder, dbs, dbmap, custom_variables))
        cmd_options = {"data_folder": vault_folder}
        if not custom_variables:
            custom_variables = {}
        for custom_var in configuration.config.custom_vars:
            if custom_var in custom_variables:
                cmd_options[custom_var] = '-' + custom_var + \
                    ' ' + str(custom_variables[custom_var])
            else:
                cmd_options[custom_var] = ''
        if dbs:
            # remove spaces from stringed json to prevent splitting by shlex and globbing in BASH
            cmd_options["dbs"] = configuration.config.databases_key + ' ' + json.dumps(dbs).replace(' ',
                                                                                                    '')
        else:
            cmd_options["dbs"] = ""
        if dbmap:
            # remove spaces from stringed json to prevent splitting by shlex and globbing in BASH
            cmd_options["dbmap"] = configuration.config.dbmap_key + ' ' + json.dumps(dbmap).replace(' ',
                                                                                                    '')
        else:
            cmd_options["dbmap"] = ""

        cmd_processed = self.__split_command_line(cmd % cmd_options)
        log.info("Run cmd template: %s\n\toptions: %s\n\tcmd: [%s]" % (
            cmd, str(cmd_options), ", ".join(cmd_processed)))
        return cmd_processed

    @staticmethod
    def __is_backup_action(action):
        return action.lower().find('backup') != -1

    @staticmethod
    def __is_restore_action(action):
        return action.lower().find('restore') != -1

    # main routine
    def __do_process(self, **kwargs):
        action = kwargs['action']
        if BackupProcessor.__is_backup_action(action):
            self.__perform_backup(kwargs['task_id'], kwargs['allow_eviction'],
                                  kwargs['dbs'], kwargs['custom_variables'], kwargs['sharded'], kwargs['external'],
                                  kwargs['vault_name'], kwargs['vault_path'])
            self.perform_evictions()
        elif BackupProcessor.__is_restore_action(action):
            self.__perform_restore(kwargs["task_id"], kwargs['vault_name'], kwargs['custom_variables'],
                                   dbs=kwargs['dbs'], dbmap=kwargs['dbmap'],
                                   vault_path=kwargs['vault_path'], external=kwargs['external'])

    # this will run anytime even if __do_process fails
    def __do_anyway(self, **kwargs):
        pass


class BackupExecutor:
    def __init__(self, _backup_processor, _inc_backup_processor):
        self.backup_processor = _backup_processor
        self.inc_backup_processor = _inc_backup_processor

    def get_processor(self, _type):
        if _type == INCREMENTAL:
            return self.inc_backup_processor
        else:
            return self.backup_processor

    def enqueue_backup(self, reason, custom_variables, allow_eviction=True, dbs=None, proc_type=FULL, sharded=False, backup_path=None):
        processor = self.get_processor(proc_type)
        dir_type = None
        if dbs and backup_path is None:
            dir_type = storage.GRANULAR
        else:
            dir_type = storage.FULL
        log.info("DIR Type: %s" % dir_type)

        if proc_type == INCREMENTAL:
            if backup_path is None:
                full_ts = self.backup_processor.storage.list(
                    timestamps_only=True, convert_to_ts=True, type=dir_type)
                inc_ts = self.inc_backup_processor.storage.list(
                    timestamps_only=True, convert_to_ts=True, type=dir_type)
                common_ts = full_ts + inc_ts
            else:
                common_ts = self.backup_processor.storage.list(timestamps_only=True, convert_to_ts=True, type=dir_type,
                                                               storage_path=backup_path)

            common_ts.sort(
                key=lambda date: datetime.fromtimestamp(date), reverse=True)

            if common_ts:
                custom_variables['start_ts'] = common_ts[0]
            else:
                raise httpapi.IllegalStateException(
                    "Existing backups not found. Previous full or incremental backups must exist"
                    " before doing incremental backup")

        return processor.enqueue_backup(reason, custom_variables, allow_eviction, dbs, sharded, backup_path)

    def enqueue_eviction(self, proc_type=FULL):
        processor = self.get_processor(proc_type)
        processor.perform_evictions()

    def enqueue_restore(self, reason, vault_name, dbs, dbmap, custom_variables, proc_type=FULL, backup_path=None):
        processor = self.get_processor(proc_type)
        return processor.enqueue_restore(reason, vault_name, dbs, dbmap, custom_variables, backup_path)

    def get_job_status(self, task_id, proc_type=FULL):
        processor = self.get_processor(proc_type)
        return processor.get_job_status(task_id)

    def get_backup_stats(self, vault_name=None, proc_type=FULL, ts=None, backup_path=None):
        processor = self.get_processor(proc_type)
        return processor.get_backup_stats(vault_name, ts, backup_path)

    def remove_backup(self, vault_name, proc_type=FULL):
        processor = self.get_processor(proc_type)
        return processor.remove_backup(vault_name)

    def update_eviction_policy(self, new_policy, proc_type=FULL):
        processor = self.get_processor(proc_type)
        processor.full_eviction_policy = new_policy
        processor.perform_evictions()

    def terminate_backup(self, vault_name, backup_path, proc_type=FULL):
        processor = self.get_processor(proc_type)
        return processor.terminate_backup(vault_name, backup_path)


def fetch_config(config_type='full'):
    if config_type == INCREMENTAL:
        config_prefix = 'incremental_'
    elif config_type == FULL:
        config_prefix = ''
    else:
        config_prefix = None

    if config_type == INCREMENTAL or config_type == FULL:
        dict = {
            'schedule': conf.get_string(config_prefix + 'schedule'),
            'granular_schedule': conf.get_string('granular_schedule'),
            'scheduled_dbs': conf.get_string('scheduled_dbs'),
            'backup_cmd': conf.get_string(config_prefix + 'command'),
            'restore_cmd': conf.get_string(config_prefix + 'restore_command'),
            'evict_cmd': conf.get_string(config_prefix + 'evict_command', default=''),
            'db_list_cmd': conf.get_string(config_prefix + 'list_instances_in_vault_command'),
            'storage_root': conf.get_string(config_prefix + 'storage'),
            'external_storage_root': conf.get_string(config_prefix + 'storage_external'),
            'eviction_policy': conf.get_string(config_prefix + 'eviction'),
            'granular_eviction_policy': conf.get_string(config_prefix + 'granular_eviction'),
            'incremental_enabled': conf.get_string('incremental_enabled'),
            'termination_cmd': conf.get_string('termination_command', default=''),
        }
        if len(dict["scheduled_dbs"]) > 0:
            dict["scheduled_dbs"] = dict["scheduled_dbs"].split(",")
        if conf.get_string('s3_enabled').lower() == "true":
            s3_dict = {
                's3_enabled': conf.get_string('s3_enabled'),
                's3_url': conf.get_string('s3_url'),
                's3_key_id': conf.get_string('s3_key_id'),
                's3_key_secret': conf.get_string('s3_key_secret'),
                's3_bucket': conf.get_string('s3_bucket'),
                's3_ssl_verify': conf.get_string('s3_ssl_verify'),
                's3_certs_path': conf.get_string('s3_certs_path')
            }
            dict.update(s3_dict)
        if conf.get_string('tls_enabled') is not None and conf.get_string('tls_enabled').lower() == "true":
            tls_dict = {
                'tls_enabled': conf.get_string('tls_enabled'),
                'certs_path': conf.get_string('certs_path'),
                'tls_port': conf.get_string('tls_port'),
            }
            dict.update(tls_dict)
        return dict
    else:
        custom_vars = {}
        for custom_var in conf.get_list("custom_vars"):
            if isinstance(custom_var, ConfigTree):
                custom_vars.update(custom_var)
            else:
                custom_vars[custom_var] = ''

        return {
            'databases_key': conf.get_string("instances_key"),
            'dbmap_key': conf.get_string("map_key"),
            'enable_full_restore': conf.get_bool("enable_full_restore"),
            'must_have_env_vars': conf.get_list("must_have_env_vars"),
            'custom_vars': custom_vars,
            'publish_custom_vars': conf.get_bool('publish_custom_vars'),
            'logs_to_stdout': conf.get_bool('logs_to_stdout')
        }


if __name__ == "__main__":
    default_config = os.path.join(
        os.path.dirname(__file__), 'backup-daemon.conf')
    if os.path.exists('/etc/backup-daemon.conf'):
        conf = ConfigFactory.parse_file(
            '/etc/backup-daemon.conf').with_fallback(default_config)
    else:
        conf = ConfigFactory.parse_file(default_config)

    log_datefmt = conf.get_string('log.datefmt', '')
    logging.basicConfig(level=conf.get_string('log.level'),
                        format=conf.get_string('log.format'),
                        datefmt=log_datefmt if log_datefmt else None)

    log = logging.getLogger("Backup")
    log.info("Start backup daemon...")

    log.info("Full configuration: %s" % conf)
    backup_cfg = fetch_config(FULL)
    log.info("Processing configuration: %s" % backup_cfg)
    inc_backup_cfg = fetch_config(INCREMENTAL)
    log.info("Incremental processing configuration: %s" % inc_backup_cfg)
    common_cfg = fetch_config('common')
    log.info("Common configuration: %s" % common_cfg)
    configuration.config = configuration.Config(common_cfg)

    broadcast_address = conf.get_string('broadcast_address')

    # TODO: check configuration values

    unset_env_vars = []
    if common_cfg['must_have_env_vars']:
        for var in common_cfg['must_have_env_vars']:
            if not (fsutil.readenv(var)):
                unset_env_vars.append(var)

    if unset_env_vars:
        log.error("The following env vars are not set, failing... %s" %
                  unset_env_vars)
        sys.exit(100)
    s3_certs_path = backup_cfg.get("s3_certs_path", "")
    if s3_certs_path != "":
        certs_dir = backup_cfg["s3_certs_path"].rstrip("/")
        cert_dir_internal = os.environ.get("S3_CERT_PATH_INTERNAL")
        certs_names = [f for f in os.listdir(certs_dir) if os.path.isfile(os.path.join(certs_dir, f))]
        with open(os.path.join(cert_dir_internal, "ca.crt"), 'w+') as ca_crt:
            for cert in certs_names:
                with open(os.path.join(certs_dir, cert)) as in_cert:
                    ca_crt.write(in_cert.read())

    backup_processor = BackupProcessor(backup_cfg, FULL)
    inc_backup_processor = BackupProcessor(inc_backup_cfg, INCREMENTAL)
    backupExecutor = BackupExecutor(backup_processor, inc_backup_processor)

    try:
        if not (fsutil.readenv("BACKUP_DAEMON_API_CREDENTIALS_USERNAME") or
                fsutil.readenv("BACKUP_DAEMON_API_CREDENTIALS_PASSWORD")):
            log.warning(
                "Backup API credentials are not set. Setting to unauth...")
            backupExecutor.login_required = False
        else:
            backupExecutor.login_required = True
    except:
        backupExecutor.login_required = False
    context = None

    port = 8080
    if 'tls_enabled' in backup_cfg and backup_cfg['tls_enabled'] is not None and backup_cfg['tls_enabled'].lower() == "true":
        path = backup_cfg['certs_path'].rstrip("/")
        context = (f'{path}/tls.crt', f'{path}/tls.key')
        port = backup_cfg['tls_port']

    log.info("Run http api server...")
    httpapi.backupExecutor = backupExecutor
    httpapi.app.run(broadcast_address, port, ssl_context=context)
