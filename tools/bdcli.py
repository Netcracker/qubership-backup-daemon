#!/usr/bin/env python
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


import argparse
import ast
import json
import logging
import os
import http.client as http_client
import sys
import time

import requests

request_headers = {
    'Content-type': 'application/json',
}
iteration_timeout = 5  # seconds


class BDClientError(Exception):
    pass


def _parse_db(db):
    try:
        return ast.literal_eval(db)
    except (ValueError, SyntaxError):
        return db


class BackupClient:
    def __init__(self, host: str, username: str, password: str, verify: str, dbs: list, properties: dict, wait: bool,
        verbose: bool, timeout: int, incremental: bool):
        if host is not None:
            self.host = host
        else:
            self.host = "https://localhost:8443" if read_env("TLS_ENABLED") == "true" else "http://localhost:8080"
        if incremental:
            self.host += "/incremental"
        username = username if username is not None else read_env("BACKUP_DAEMON_API_CREDENTIALS_USERNAME")
        password = password if password is not None else read_env("BACKUP_DAEMON_API_CREDENTIALS_PASSWORD")
        self.auth = None if username is None or password is None else (username, password)
        self.verify = verify if verify is not None else f'{read_env("CERTS_PATH")}/ca.crt'
        self.dbs = dbs
        self.properties = properties
        self.wait = wait
        self.timeout = timeout
        self.verbose = verbose

        if self.verbose:
            http_client.HTTPConnection.debuglevel = 1
            logging.basicConfig()
            logging.getLogger().setLevel(logging.DEBUG)
            requests_log = logging.getLogger("requests.packages.urllib3")
            requests_log.setLevel(logging.DEBUG)
            requests_log.propagate = True

    def _log(self, message: str):
        if self.verbose:
            print(message)

    def _build_body(self):
        body = {}

        if self.dbs:
            body["dbs"] = [_parse_db(item) for item in self.dbs]
        if self.properties:
            body.update(self.properties)
        return body

    def _retry_status(self, job_id):
        self._log(f"Try to get status for job_id '{job_id}'")
        start_time = time.time()
        while True:
            # Perform the request and get the response JSON
            status = self.get_status(job_id)
            response_json = json.loads(status)
            self._log(f"Status for '{job_id}' is '{response_json}'")

            if response_json.get('status') == 'Successful':
                return
            current_time = time.time()
            if current_time - start_time >= self.timeout:
                self._log("Timeout reached. Exiting.")
                raise BDClientError(status)

            self._log(f"Attempt failed. Retrying in {iteration_timeout} seconds...")
            time.sleep(iteration_timeout)

    def perform_backup(self):
        self._log("Start backup process")
        resp = requests.post(url=f"{self.host}/backup", auth=self.auth, data=json.dumps(self._build_body()),
                             headers=request_headers, verify=self.verify)
        if resp.status_code != 200:
            self._log(f"Error executing request, Response: Status-Code: {resp.status_code}, Content: {resp.text}")
            raise BDClientError(resp.text)
        backup_id = resp.text
        if self.wait:
            self._retry_status(backup_id)
        return backup_id

    def perform_restore(self, backup_id: str):
        if backup_id is None:
            raise BDClientError("Restore cannot be run with empty <backup_id> or <timestamp>")
        self._log(f"Start restore process for backup_id '{backup_id}'")
        body = self._build_body()
        if is_valid_timestamp(backup_id):
            body["ts"] = backup_id
        else:
            body["vault"] = backup_id
        resp = requests.post(url=f"{self.host}/restore", auth=self.auth, data=json.dumps(body), headers=request_headers,
                             verify=self.verify)
        if resp.status_code != 200:
            self._log(f"Error executing request, Response: Status-Code: {resp.status_code}, Content: {resp.text}")
            raise BDClientError(resp.text)
        restore_id = resp.text
        if self.wait:
            self._retry_status(restore_id)
        return restore_id

    def perform_evict(self, backup_id: str):
        if backup_id is None:
            resp = requests.post(url=f"{self.host}/evict", auth=self.auth, verify=self.verify)
        else:
            resp = requests.post(url=f"{self.host}/evict/{backup_id}", auth=self.auth, verify=self.verify)
        if resp.status_code != 200:
            self._log(f"Error executing request, Response: Status-Code: {resp.status_code}, Content: {resp.text}")
            raise BDClientError(resp.text)
        restore_id = resp.text
        return restore_id

    def get_backup_list(self):
        self._log("Getting backup list...")
        resp = requests.get(url=f"{self.host}/listbackups", auth=self.auth, verify=self.verify)
        if resp.status_code != 200:
            self._log(f"Error executing request, Response: Status-Code: {resp.status_code}, Content: {resp.text}")
            raise BDClientError(resp.text)
        return resp.text

    def describe_backup(self, backup_id: str):
        if backup_id is None:
            raise BDClientError("Describe cannot be run with empty <backup_id> or <timestamp>")
        if is_valid_timestamp(backup_id):
            resp = requests.get(url=f"{self.host}/find", auth=self.auth, data=json.dumps({"ts": backup_id}),
                                headers=request_headers,
                                verify=self.verify)
        else:
            resp = requests.get(url=f"{self.host}/listbackups/{backup_id}", auth=self.auth, verify=self.verify)
        if resp.status_code > 400:
            self._log(f"Error executing request, Response: Status-Code: {resp.status_code}, Content: {resp.text}")
            raise BDClientError(resp.text)
        return resp.text

    def get_status(self, job_id: str):
        if job_id is None:
            raise BDClientError("Status cannot be run with empty <backup_id> or <timestamp>")
        resp = requests.get(url=f"{self.host}/jobstatus/{job_id}", auth=self.auth, verify=self.verify)
        if resp.status_code > 400:
            self._log(f"Error executing request, Response: Status-Code: {resp.status_code}, Content: {resp.text}")
            raise BDClientError(resp.text)
        return resp.text


def str2bool(v):
    # Function to convert string representation of boolean values to actual booleans
    return v.lower() in ("true", "t", "1")


def is_valid_timestamp(timestamp: str):
    try:
        timestamp = int(timestamp)
        return timestamp >= 0
    except ValueError:
        return False


def save_to_file(backup_id: str, file: str):
    with open(file, 'w') as file:
        file.write(backup_id)


def load_from_file(file: str):
    with open(file, 'r') as file:
        return file.read()


class KeyValueAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        # Split the key=value inputs and create a dictionary entry for each pair
        properties = getattr(namespace, self.dest) or {}
        for pair in values:
            key, value = pair.split("=")
            properties[key] = value
        setattr(namespace, self.dest, properties)


def read_env(var):
    if var in os.environ:
        return os.environ[var]
    else:
        return None


def create_parser():
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("--username", "-u", type=str,
                               help="The username of Backup Daemon API. By default the value of 'BACKUP_DAEMON_API_CREDENTIALS_USERNAME' environment variable is used.")
    common_parser.add_argument("--password", "-p", type=str,
                               help="The password of Backup Daemon API. By default the value of 'BACKUP_DAEMON_API_CREDENTIALS_PASSWORD' environment variable is used.")
    common_parser.add_argument("--host", type=str,
                               help="The url address of Backup Daemon REST API. By default the local address is used `http(s)://localhost:8080(8443)`.")
    common_parser.add_argument("--verify", type=str,
                               help="The path to CA certificate to verify HTTPS connection or `false` to disable it. By default the value of `{CERTS_PATH}/ca.crt' is used.")
    common_parser.add_argument("--incremental", "-i", action="store_true",
                               help="Use incremental API for execution commands. Default false.")
    common_parser.add_argument("--verbose", "-v", action="store_true",
                               help="Verbose output of executing commands. By default it responses with final output of Backup Daemon API only.")
    common_parser.add_argument("--wait", "-w", action="store_true",
                               help="Wait for command execution for async commands like `backup` or `restore`. By default all commands are asynchronous.")
    common_parser.add_argument("--timeout", "-t", type=int, default=60,
                               help="Timeout for commands execution (in seconds). By default: 60.")
    common_parser.add_argument("--dbs", nargs='+', type=str,
                               help="Databases to perform operation delimited by space. If not specified - all databases are used.")
    common_parser.add_argument("--properties", nargs="+", action=KeyValueAction,
                               help="Additional properties as key=value delimited by space.")
    common_parser.add_argument("--input", "--in", type=str, default=None,
                               help="Specify the path to the file with input data for command.")
    common_parser.add_argument("--output", "--out", type=str, default=None,
                               help="Specify the path to the file with output data of command.")

    parser = argparse.ArgumentParser(description="Backup Daemon CLI is a shell client for Backup Daemon REST API.",
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     epilog="Examples:"
                                            "\n\n"
                                            "bdcli backup\n"
                                            "bdcli restore 20230303T101010\n"
                                            "bdcli restore 1692321321312 --dbs database1 database2 --properties cluster=aws mode=all --wait\n"
                                            "bdcli describe 20230303T101010\n"
                                            "bdcli status 66a0f51b-e6ac-4e89-b2c7-48774ed05a7c")
    subparsers = parser.add_subparsers(title="commands", dest="command")

    backup_parser = subparsers.add_parser("backup", aliases=["b"], parents=[common_parser],
                                          help="Perform backup. Returns <backup_id>.",
                                          formatter_class=argparse.RawTextHelpFormatter,
                                          epilog="Examples:"
                                                 "\n\n"
                                                 "bdcli backup\n"
                                                 "bdcli backup --dbs database1 database2 --properties cluster=aws mode=all --wait\n"
                                                 "bdcli backup --out /backup-storage/latest-id")

    restore_parser = subparsers.add_parser("restore", aliases=["r"],
                                           parents=[common_parser],
                                           help="Perform restore. Must be used with backup identifier `restore <backup_id>` or `restore <timestamp>`. Returns <job_id>.",
                                           formatter_class=argparse.RawTextHelpFormatter,
                                           epilog="Examples:"
                                                  "\n\n"
                                                  "bdcli restore 20230303T101010\n"
                                                  "bdcli restore 1692321321312\n"
                                                  "bdcli restore --in /backup-storage/latest-id --dbs database1 database2 --properties cluster=aws mode=all --wait\n")
    restore_parser.add_argument("backup_id", nargs="?", type=str, help="Backup identifier <backup_id> or <timestamp>")

    list_parser = subparsers.add_parser("list", aliases=["l"], parents=[common_parser], help="List backups")

    describe_parser = subparsers.add_parser("describe", aliases=["get", "d"], parents=[common_parser],
                                            help="Describe backup. Must be used with backup identifier `describe <backup_id>` or `describe <timestamp>`.")
    describe_parser.add_argument("backup_id", nargs="?", type=str, help="Backup identifier <backup_id> or <timestamp>")

    status_parser = subparsers.add_parser("status", aliases=["s"], parents=[common_parser],
                                          help="Describe status of operation. Must be used with job identifier `status <job_id>`")
    status_parser.add_argument("job_id", nargs="?", type=str, help="Job ID to describe.")

    evict_parser = subparsers.add_parser("evict", aliases=["e"], parents=[common_parser],
                                         help="Evict backup. Can be used with backup identifier `evict <backup_id>`. If used without parameters all evictable backups will be removed.")
    evict_parser.add_argument("backup_id", nargs="?", type=str, help="Backup ID to evict.")

    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()

    if args.command:
        backup_client = BackupClient(host=args.host, username=args.username, password=args.password, verify=args.verify,
                                     dbs=args.dbs, properties=args.properties, wait=args.wait, verbose=args.verbose,
                                     timeout=args.timeout, incremental=args.incremental)
        output = ""
        if args.command == "backup" or args.command == "b":
            output = backup_client.perform_backup()
        elif args.command == "restore" or args.command == "r":
            backup_id = args.backup_id
            if args.input:
                backup_id = load_from_file(args.input)
            output = backup_client.perform_restore(backup_id)
        elif args.command == "list" or args.command == "l":
            output = backup_client.get_backup_list()
        elif args.command == "describe" or args.command == "d" or args.command == "get":
            backup_id = args.backup_id
            if args.input:
                backup_id = load_from_file(args.input)
            output = backup_client.describe_backup(backup_id)
        elif args.command == "status" or args.command == "s":
            job_id = args.job_id
            if args.input:
                job_id = load_from_file(args.input)
            output = backup_client.get_status(job_id)
        elif args.command == "evict" or args.command == "e":
            backup_id = args.backup_id
            if args.input:
                backup_id = load_from_file(args.input)
            output = backup_client.perform_evict(backup_id)
        else:
            parser.print_help()
        print(output)
        if args.output:
            save_to_file(output, args.output)
    else:
        parser.print_help()


if __name__ == "__main__":
    try:
        main()
    except BDClientError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
