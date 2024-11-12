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
import threading
import time
import uuid
from queue import Queue, Empty
from croniter import croniter
from datetime import datetime
from threading import Thread

import configuration
from constants import *


class Scheduler(Thread):
    __log = logging.getLogger("Scheduler")

    def __init__(self, schedule, callback, run_always_callback, *callback_args, dbs=None):
        Thread.__init__(self)
        self.setDaemon(True)
        self.__log.info("Start scheduler with: %s" % schedule)
        if croniter.is_valid(schedule):
            self.__cron = croniter(schedule)
        else:
            self.__cron = None
        self.__task_queue = Queue()
        self.__callback_func = callback
        self.__run_always_callback_func = run_always_callback
        self.__callback_args = callback_args
        self.dbs = dbs
        if self.__cron:
            self.__reschedule()

    def queue_size(self):
        return self.__task_queue.qsize()

    @staticmethod
    def generate_task_id():
        return str(uuid.uuid4())

    def __reschedule(self):
        self.__next_timestamp = self.__cron.get_next()
        time_to_run = datetime.fromtimestamp(self.__next_timestamp).strftime("%Y-%m-%d %H:%M:%S")
        if self.dbs is not None:
            self.__log.info(
                f"scheduled next backup for {self.dbs} at {time_to_run}")
        else:
            self.__log.info(
                f"scheduled next backup at {time_to_run}")

        # TODO check on negative value after substraction
        delay = self.__next_timestamp - time.time()
        if (delay < 0):
            self.__log.warn(
                "Task execution performed longer than specified repeat interval")
            delay = 0

        self.timer = threading.Timer(delay, self.__execute_and_reschedule)
        self.timer.setDaemon(True)
        self.timer.start()

    def __execute_and_reschedule(self):
        self.__log.info("Enqueue backup execution...")
        custom_variables = \
            {k: v for k, v in configuration.config.custom_vars.items() if v}
        self.enqueue_execution(reason="cron", action="backup", dbs=self.dbs,
                               custom_variables=custom_variables)
        self.__reschedule()

    def __merge_dicts(self, y):
        z = self.copy()
        z.update(y)
        return z

    def run(self):
        while True:
            try:
                callback_args = {}
                queue_item = self.__task_queue.get(True, timeout=1)
                reason = queue_item['reason']
                callback_args['dbs'] = queue_item['dbs']
                callback_args['action'] = queue_item['action']
                callback_args['vault_name'] = queue_item['vault_name']
                callback_args['task_id'] = queue_item['task_id']
                callback_args['external'] = queue_item['external']
                callback_args['vault_path'] = queue_item['vault_path']
                callback_args['allow_eviction'] = queue_item['allow_eviction']
                callback_args['sharded'] = queue_item['sharded']
                callback_args['dbmap'] = queue_item['dbmap']
                callback_args['custom_variables'] = queue_item['custom_variables']
            except Empty:
                continue
            except:
                self.__log.error(
                    "Error executing schedule callback", exc_info=1)
                continue
            try:
                self.__log.info("Execute callback by: %s, with args: %s, queue length: %d" % (
                    reason, callback_args, self.__task_queue.qsize()))
                (f, kwargs) = (self.__callback_func, callback_args)
                f(**kwargs)
            except:
                self.__log.error(
                    "Error executing schedule callback", exc_info=1)
            finally:
                try:
                    (f, kwargs) = (self.__run_always_callback_func, callback_args)
                    f(**kwargs)
                except:
                    self.__log.error(
                        "Error executing schedule run_always_callback", exc_info=1)
                self.__task_queue.task_done()

    def enqueue_execution(self, action, reason="manual call", allow_eviction=True, vault_name="", dbs=None, dbmap=None,
                          task_id=None, custom_variables=None, sharded=False, external=False, vault_path=None):
        self.__log.info("Enqueue %s by: %s. Queue length: %d" %
                        (action, reason, self.__task_queue.qsize()))
        if not task_id:
            if action == COMMON_BACKUP or action == INCREMENTAL_BACKUP:
                vault_name_format = "%Y%m%dT%H%M%S"
                task_id = datetime.now().strftime(vault_name_format)
            else:
                task_id = self.generate_task_id()

        self.__task_queue.put({"reason": reason,
                               "task_id": task_id,
                               "action": action,
                               "allow_eviction": allow_eviction,
                               "sharded": sharded,
                               "vault_name": vault_name,
                               "external": external,
                               "vault_path": vault_path,
                               "dbs": dbs,
                               "dbmap": dbmap,
                               "custom_variables": custom_variables})
        self.__log.info(
            "Enqueued %s by: %s. Queue length: %d. task_id:%s" % (action, reason, self.__task_queue.qsize(), task_id))
        return task_id
