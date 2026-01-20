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
import apsw


log = logging.getLogger("Database")
DB_BUSY_TIMEOUT = 10000


def row_factory(cursor, row):
    return {k[0]: row[i] for i, k in enumerate(cursor.getdescription())}


class DbException(Exception):
    pass


class DB:
    _lock = threading.Lock()
    
    def __init__(self, dbfile):
        """
        Create a connection to sqlite database
        :param dbfile: database file

        :__conn: connection object
        :__cursor: cursor object
        :__tableName: table name for jobs
        """
        self.__dbfile = dbfile
        try:
            log.debug("Database file: %s" % self.__dbfile)
            self.__conn = DB.__create_connection(dbfile)
        except apsw.Error as err:
            log.exception("Database error during init: %s" % err)
            raise DbException("Database error during init")
        self.__tableName = "jobs"
        jobs_table_query = """
            CREATE TABLE
            IF NOT EXISTS %s (
            task_id text PRIMARY_KEY,
            type test NOT NULL,
            status text NOT NULL,
            vault text,
            err text
            )
        """ % self.__tableName
        self.__create_table(jobs_table_query)

    @staticmethod
    def __create_connection(db_file):
        conn = apsw.Connection(db_file, vfs="unix-dotfile")
        conn.setrowtrace(row_factory)
        conn.setbusytimeout(DB_BUSY_TIMEOUT)
        return conn

    def __create_table(self, query):
        try:
            cursor = self.__conn.cursor()
            with cursor:
                cursor.execute(query)
        except apsw.Error as err:
            log.exception("Database Error: %s" % err)
            return 0

    @staticmethod
    def __log_and_execute(cursor, sql, args):
        with DB._lock:
            log.debug("SQL command: " + sql.replace('?', '%s') % args)
            cursor.execute(sql, args)

    def __insert_or_delete(self, query, params, login=False):
        try:
            if login:
                cursor = DB.__create_connection(self.__dbfile).cursor()
            else:
                cursor = self.__conn.cursor()
            with cursor:
                DB.__log_and_execute(cursor, query, params)
            return 1
        except apsw.Error as err:
            log.exception("Database Error: %s" % err)
            return 0

    def __select(self, query, params, login=False):
        try:
            if login:
                cursor = DB.__create_connection(self.__dbfile).cursor()
            else:
                cursor = self.__conn.cursor()
            with cursor:
                DB.__log_and_execute(cursor, query, params)
                return cursor.fetchall()
        except apsw.Error as err:
            log.exception("Database Error: %s" % err)
            return None

    def update_job(self, task_id, type, status, vault, error, login=False):
        # this is required as java json convertion fails for None value of error
        if error is None:
            error = ''
        if not task_id:
            error_message = "Database insert error: task_id not specified"
            log.exception(error_message)
            raise DbException(error_message)
        if self.__select("SELECT * FROM %s WHERE task_id = ?" % self.__tableName, (task_id,), login=login):
            if not self.__insert_or_delete(
                    "UPDATE " + self.__tableName + " SET 'type'=?, 'status'=?, 'vault'=?, 'err'=? where task_id=?",
                    (type, status, vault, error, task_id), login=login):
                log.error("Unable to update jobs database")
        else:
            if not self.__insert_or_delete("INSERT INTO " + self.__tableName + " VALUES(?, ?, ?, ?, ?)",
                                           (task_id, type, status, vault, error), login=login):
                log.error("Unable to insert to jobs database")

    def rm_vault_from_base(self, vault, login=False):
        if not vault:
            error_message = "Database insert error: task_id not specified"
            log.exception(error_message)
            raise DbException(error_message)
        task_from_db = self.__select("SELECT * FROM %s WHERE vault = ?" % self.__tableName, (vault,), login=login)
        if task_from_db is None or len(task_from_db) < 1:
            log.warning(f"Task {vault} not found in DB")
            return
        task_id = task_from_db[0]['task_id']

        if not self.__insert_or_delete("DELETE FROM " + self.__tableName + " WHERE vault=(?)", (vault,), login=login):
            log.error("Unable to delete vault %s from jobs database" % vault)

        # clean up Queued and Failed
        if not self.__insert_or_delete("DELETE FROM " + self.__tableName + " WHERE task_id=(?)", (task_id,),
                                       login=login):
            log.error("Unable to delete vault %s from jobs database with task_id %s" % (vault, task_id))

    def select_everything(self, task_id, login=False):
        return self.__select("SELECT * FROM %s WHERE task_id = ?" % self.__tableName, (task_id,), login=login)
