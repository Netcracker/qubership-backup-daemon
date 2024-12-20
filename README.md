# Backup Daemon release process

- [Backup daemon release process](#backup-daemon-release-process)
  - [Pull requests](#pull-requests)
  - [Release](#release)
  - [Contributing](#contributing)
  - [Eviction Policy](#eviction-policy)
  - [Custom variables](#custom-variables)
  - [S3 storage](#s3-storage)
  - [API](#api)
    - [Swagger UI](#swagger-ui)
    - [API Usage](#api-usage)
      - [Run the Full Manual Backup](#run-the-full-manual-backup)
      - [Run the Incremental Manual Backup](#run-the-incremental-manual-backup)
      - [Run the Manual Backup For Some Subset of dbs (granular backup)](#run-the-manual-backup-for-some-subset-of-dbs-granular-backup)
      - [Run Manual Backup, Passing dbs](#run-manual-backup-passing-dbs)
      - [Run Manual Backup That Will Not Be Deleted Ever](#run-manual-backup-that-will-not-be-deleted-ever)
      - [Run Manual Backup that will be stored at NFS](#run-manual-backup-that-will-be-stored-at-nfs)
      - [Run Manual Eviction](#run-manual-eviction)
      - [Remove specific backup by id](#remove-specific-backup-by-id)
      - [Get Health](#get-health)
      - [Run Recovery](#run-recovery)
      - [Run External Restore (managed database)](#run-external-restore-managed-database)
      - [Get Backup/Recovery Status](#get-backuprecovery-status)
      - [List Backups](#list-backups)
      - [Find Backup](#find-backup)
      - [Get Backup Information](#get-backup-information)
      - [Upload/Download API](#uploaddownload-api)
    - [Termination API](#termination-api)
  - [CLI Usage](#cli-usage)

## Pull requests
 * 
## Release

The base repository is available to make various backup daemons for different databases such as Mongo, and Postgresql.
It provides REST API and schedule backups.

## Contributing

To build a service-specific backup daemon, follow the steps given below.

* Fork a new repository.
* Create a backup script/scripts in any language you want to handle the backup process.
  It must take at least one argument - vault folder (a directory where the newly created backup should be stored).
* Create a **backup-daemon.conf** file with the following code : `put _%(data_folder)s_,  _%(dbs)s_ and _%(dbmap)s_` .

The config file parameters are given below.

<!-- markdownlint-disable line-length -->
| Option                          | Default                                                                         | Description                                                                                                                                                              | Environment variable     |
|---------------------------------|---------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------|
| schedule                        | `0 * * * *`                                                                     | Cron-like backup schedule. Set to 'None' to disable auto backups                                                                                                         | BACKUP_SCHEDULE          |
| eviction                        | `7d/7d,1y/delete`                                                               | Eviction policy                                                                                                                                                          | EVICTION_POLICY          |
| granular_eviction               | `7d/delete`                                                                     | Eviction policy for granular backups                                                                                                                                     | GRANULAR_EVICTION_POLICY |
| storage                         | `/backup-storage`                                                               | Backup storage mountpoint, don't edit this unless you sure what you are doing                                                                                            | STORAGE                  |
| instances_key                   | `-d`                                                                            | Backend script key to pass instances for granular backups (for example, specific dbs/collections for mongoDB)                                                            |                          |
| map_key                         | `-m`                                                                            | Backend script key to pass json with re-naming map for restoring backups                                                                                                 |                          |
| command                         | `ls -la %(data_folder)s`                                                        | Backend script call to run backup                                                                                                                                        |                          |
| restore_command                 | `ls -la %(data_folder)s`                                                        | Backend script call to run restore                                                                                                                                       |                          |
| evict_command                   | `rm %(data_folder)s`                                                            | Backend script call to evict backup in addition to default behavior for eviction procedure (Can be empty)                                                                |                          |
| termination_command             |                                                                                 | Backend script call to terminate backup process by killing active backup command by pid and run custom command if it is provided (Can be empty)                          |                          |
| list_instances_in_vault_command | `ls -la %(data_folder)s`                                                        | Backend script call to list instances from vault                                                                                                                         |                          |
| must_have_env_vars              |                                                                                 | List of env vars names.Backup daemon will fail immediately, if any of these env vars is not set                                                                          |                          |
| custom_vars                     |                                                                                 | List of custom variables, that will be used in custom commands implementation. For more information see [Custom Variables](#custom-variables) section                    |                          |
| publish_custom_vars             | `false`                                                                         | Whether the non-empty values of custom variables need to be stored to the `.custom_vars` file for further display when getting information about the backup              |                          |
| broadcast_address               |                                                                                 | The hostname for REST API to listen on. Set this to `"0.0.0.0"` to have the server available externally for IPv4 environment or `"::"` for IPv6. Defaults to `"0.0.0.0"` | BROADCAST_ADDRESS        |
| log['level']                    | `INFO`                                                                          | Log level, can be DEBUG,INFO,WARNING,ERROR, you can set it in LOG_LEVEL env var                                                                                          |                          |
| log['format']                   | `"[%(asctime)s][%(levelname)s][class=%(name)s][thread=%(thread)d] %(message)s"` | Logging format                                                                                                                                                           |                          |
| log['datefmt']                  | `"%Y-%m-%dT%H:%M:%S%z"`                                                         | Logging date/time format (default ISO8601)                                                                                                                               |                          |
| s3_enabled                      | `false`                                                                         | Enable to save backups to S3 storage                                                                                                                                     | S3_ENABLED               |
| s3_url                          |                                                                                 | URL of a S3 storage                                                                                                                                                      | S3_URL                   |
| s3_key_id                       |                                                                                 | Key ID for the S3 storage                                                                                                                                                | S3_KEY_ID                |
| s3_key_secret                   |                                                                                 | Key secret for the S3 storage                                                                                                                                            | S3_KEY_SECRET            |
| s3_bucket                       |                                                                                 | Bucket in the S3 storage                                                                                                                                                 | S3_BUCKET                |
| s3_ssl_verify                   |                                                                                 | Whether or not to verify SSL certificates for S3 connections                                                                                                             | S3_SSL_VERIFY            |
| s3_certs_path                   | `""`                                                                            | Path to folder with TLS certificates for S3 connections, only takes effect if `s3_ssl_verify` is `true`. Value `""` means that boto3 default certificates will be used   | S3_CERTS_PATH            |
| tls_enabled                     | `false`                                                                         | Whether TLS is enabled                                                                                                                                                   | TLS_ENABLED              |
| allow_prefix                    |                                                                                 | Allow specify additional prefix for granular backups                                                                                                                     | ALLOW_PREFIX             |
| certs_path                      | `/tls/`                                                                         | Path to folder with TLS certificates                                                                                                                                     | CERTS_PATH               |
| logs_to_stdout                  | `false`                                                                         | Prints logs from .console and ${restore-id}.log to stdout (pod logs)                                                                                                     | LOGS_TO_STDOUT           |
<!-- markdownlint-enable line-length -->

For example:

```toml
{
    command = $BACKUP_COMMAND_WITH_NEEDED_ARGS %(data_folder)s %(dbs)s %(dbmap)
    restore_command = $RESTORE_COMMAND_WITH_NEEDED_ARGS %(data_folder)s %(dbs)s %(dbmap)
    list_instances_in_vault_command = $LIST_COMMAND_WITH_NEEDED_ARGS %(data_folder)s %(dbs)s %(dbmap)
    must_have_env_vars = [
        VAR1,
        VAR2
    ]
    custom_vars = [VAR3]
}
```

Add a secret containing `BACKUP_DAEMON_API_CREDENTIALS_USERNAME` and `BACKUP_DAEMON_API_CREDENTIALS_PASSWORD`
env parameter to a **template.json** of your fork and mount it as ENV to your RC/DC.

Make a dockerfile to build a docker image, it should fork latest `backup-daemon` image.

Do not forget to add `chmod +x` to your script.

## Eviction Policy

Eviction policy is a comma-separated string of policies written as `$start_time/$interval`.
This policy splits all backups older then `$start_time` to numerous time intervals `$interval` time long.
Then it deletes all backups in every interval except the newest one.

For example:

* `1d/7d` policy means "take all backups older than one day, split them in groups by 7-days interval,
  and leave only the newest"
* `0/1h` means "take all backups older than now, split them in groups by 1 hour and leave only the newest"

Also there is another format of policy - `$limitOfcopies/delete` where `$limitOfcopies` means how many backups
are stored in daemon.

There is possibility to update eviction policy in runtime with the following command:

```shell
curl -XPOST -u username:password -v -H "Content-Type: application/json" -d '{"fullEvictionPolicy": "3/delete"}' localhost:8080/evictionpolicy
```

## Custom variables

`custom_vars` parameter is a comma-separated list of custom variables that will be used in the
implementation of custom commands (`command`, `restore_command`). Each custom variable description
must contain its name and may contain default value. These default values are used when executing
command both on schedule and on demand, but in the latter case they can be overridden by request
body parameters. This parameter is optional.

To specify immutable default value, add element into list in the following format: `{key: "value"}`.
To specify default value depending on an environment variable, add element into list in the following
format: `{key: "value", key: ${?ENV_VAR}}`. Do not forget to define a value (even empty) for the case
when the environment variable is not specified, because a variable without a value is not included
in the configuration. If you do not need a default value for a custom variable, specify it as
follows: `key`. All above cases can be specified in the list as follows:

```toml
[{key: "value"}, {param: "", param: ${?PARAM}}, var]
```

For example, you need `mode` variable, because it should determine the way of performing the backup.
In this case you should specify `mode` variable in `custom_vars` parameter with default value, if it
is necessary, and also add the variable to `backup` command:

```ini
command = $BACKUP_COMMAND_WITH_NEEDED_ARGS %(data_folder)s %(mode)s
```

Then a user will be able to specify this variable in the request body if he wants to affect the way
of performing the backup:

```bash
curl -XPOST -u username:password -v -H "Content-Type: application/json" -d '{"dbs":["db_name1","db_name2"], "mode":"all"}' localhost:8080/backup
```

In common case command should be executed with default settings.

## S3 storage

Backups can be stored to s3 storage(AWS, Google, MinIO, etc.).

A clipboard storage is needed to be mounted to backup daemon, it can be an emptyDir volume.
As soon as backup is uploaded to S3, it's removed from the clipboard storage.

Same way works a restore procedure - a backup is downloaded from S3 to the clipboard and restored from it,
then it's removed from the clipboard but stays on S3. Eviction removes backups directly from S3.

## API

For POST operations you must specify user/pass from `BACKUP_DAEMON_API_CREDENTIALS_USERNAME` and
`BACKUP_DAEMON_API_CREDENTIALS_PASSWORD` env parameters so that you can use REST api to run backup tasks.

### Swagger UI

Swagger UI is available by address:

```bash
http://<ip>:8080/swagger-ui
```

### API Usage

This section describe how to use API endpoints and provide examples of these usage.

#### Run the Full Manual Backup

This step returns backup folder (vault) as a plain-text response. You can later use this vault name to get
a backup status (7):

```bash
curl -XPOST  -u  username:password localhost:8080/backup
```

#### Run the Incremental Manual Backup

This request returns backup folder (vault) as a plain-text response.
You can later use this vault name to get a backup status:

```bash
curl -XPOST -u username:password localhost:8080/incremental/backup
```

#### Run the Manual Backup For Some Subset of dbs (granular backup)

TBD

#### Run Manual Backup, Passing dbs

You can also pass a list of collections for every db backed, and specify query for every collection
if needed using the following query:
[https://docs.mongodb.com/manual/reference/program/mongodump/#cmdoption-mongodump-query](https://docs.mongodb.com/manual/reference/program/mongodump/#cmdoption-mongodump-query)

This returns backup folder (vault) as a plain-text response.
You can later use this vault name to get a backup status (7).

For dbs use the following command:

```bash
curl -XPOST -u username:password -v -H "Content-Type: application/json" -d '{"dbs":["db_name1","db_name2"]}' localhost:8080/backup
```

For Dbs with collections use the following command:

```bash
curl -XPOST -u username:password -v -H "Content-Type: application/json" -d '{"dbs":["db_name1",{"db_name2":{"collections":["first","second"]}]}' localhost:8080/backup
```

For DBs with collections and queries use the following command:

```bash
curl -XPOST -u username:password -v -H "Content-Type: application/json" -d '{"dbs":["db_name1",{"db_name2":{"collections":["first",{"second":{"test1":"1"}}]}]}' localhost:8080/backup
```

It is possible to add custom prefix for folder (vault):  
***NOTE***: to make it possible you have to specify ENV `ALLOW_PREFIX:true` 
```bash
curl -XPOST -u username:password -v -H "Content-Type: application/json" -d '{"dbs":["db_name1","db_name2"], "prefix":"custom"}' localhost:8080/backup
```

Returned vault name will be like `<prefix>_<namespace>_<timestamp>`.  
So `<prefix>` is optional, but `<namespace>` addition is default for `ALLOW_PREFIX:true` (namespace will be picked from `WATCH_NAMESPACE` ENV)

#### Run Manual Backup That Will Not Be Deleted Ever

If you do not want your backup to be evicted, add `allow_eviction":"False"` to your request. It works both for full
and granular backups:

```bash
curl -XPOST -u username:password -v -H "Content-Type: application/json" -d '{"allow_eviction":"False","dbs":["arg1","arg2"]}' localhost:8080/backup
```

#### Run Manual Backup that will be stored at NFS

Need to use externalBackupPath parameter.
This returns backup folder (vault) as a plain-text response.  You can later use this vault name to get a backup status (7).

```bash
curl -XPOST -u username:password -v -H "Content-Type: application/json" -d '{"externalBackupPath": "YYYYMMDDHHmmSS/mongo"}' localhost:8080/backup
```

#### Run Manual Eviction

For manual eviction use the following command:

```bash
curl -XPOST -u username:password localhost:8080/evict
```

Use the following request for incremental backups manual eviction:

```bash
curl -XPOST -u username:password localhost:8080/incremental/evict
```

#### Remove specific backup by id

For removing full backups:

```bash
curl -XPOST -u username:password localhost:8080/evict/backupid
```

For removing incremental backups:

```bash
curl -XPOST -u username:password localhost:8080/incremental/evict/backupid
```

returns 200 for OK

#### Get Health

The Get Health method returns Json with the following information:

```bash
"status": status of backup daemon
"backup_queue_size": backup daemon queue size (if > 0 then there are 1 or tasks waiting for execution)
 "storage": storage info:
  "total_space": total storage space in bytes
  "dump_count": number of backups
  "free_space": free space left in bytes
  "size": used space in bytes
  "total_inodes": total number of inodes on storage
  "free_inodes": free number of inodes on storage
  "used_inodes": used number of inodes on storage
  "last": last backup metrics
    "metrics['exit_code']": exit code of script 
    "metrics['exception']": python exception if backup failed
    "metrics['spent_time']": spent time
    "metrics['size']": backup size in bytes
    "failed": is failed or not
    "locked": is locked or not
    "sharded": is sharded or not
    "id": vault name of backup
    "ts": timestamp of backup  
  "lastSuccessful": last succesfull backup metrics
    "metrics['exit_code']": exit code of script 
    "metrics['spent_time']": spent time
    "metrics['size']": backup size in bytes
    "failed": is failed or not
    "locked": is locked or not
    "sharded": is sharded or not
    "id": vault name of backup
    "ts": timestamp of backup
```

Use the commands below to get JSON health:

For full backups storage:

```bash
curl -XGET localhost:8080/health
```

For incremental backups storage:

```bash
curl -XGET localhost:8080/incremental/health
```

Also the Get Health method returns Prometheus metrics with the following names:

```prometheus
backup_queue_size : backup daemon queue size
backup_daemon_status : status of backup daemon (1.0 if "UP", 0.0 otherwise)
backup_storage_dump_count : number of backups
backup_storage_free_inodes : free number of inodes on storage
backup_storage_free_space : free space left in bytes
backup_storage_last_failed{id="last_backup_id in format yyyymmddThhmmss"} : is last backup failed or not
backup_storage_last_locked{id="last_backup_id"} : is last backup locked or not
backup_storage_last_exit_code{id="last_backup_id"} : exit code of script
backup_storage_last_size{id="last_backup_id"} : backup size in bytes
backup_storage_last_spent_time{id="last_backup_id"} : spent time
backup_storage_last_sharded{id="last_backup_id"} : is last backup sharded or not
backup_storage_last_timestamp{id="last_backup_id"} : timestamp of backup
backup_storage_last_successful_failed{id="last_successful_backup_id"} : is last backup failed or not
backup_storage_last_successful_locked{id="last_successful_backup_id"} : is last backup locked or not
backup_storage_last_successful_exit_code{id="last_successful_backup_id"} : exit code of script
backup_storage_last_successful_size{id="last_successful_backup_id"} : backup size in bytes
backup_storage_last_successful_spent_time{id="last_successful_backup_id"} : spent time
backup_storage_last_successful_sharded{id="last_successful_backup_id"} : is last backup sharded or not
backup_storage_last_successful_timestamp{id="last_successful_backup_id"} : timestamp of backup
backup_storage_size : used space in bytes
backup_storage_inodes_total : total number of inodes on storage
backup_storage_space_total : total storage space in bytes
backup_storage_used_inodes : used number of inodes on storage
```

Use the commands below to get health in Prometheus metrics:

For full backups storage:

```bash
curl -XGET localhost:8080/health/prometheus
```

For incremental backups storage:

```bash
curl -XGET localhost:8080/incremental/health/prometheus
```

#### Run Recovery

You must specify json with vault or timestamp(optional), if vault parameter presented timestamp will be ignored,
if timestamp presented backup with equal or newer timestamp will be restored.
You must specify databases in the dbs list. You will not be able to run a recovery without database specified.

You will receive `task_id` as a response. Use it in (7) to get the status of recovery:

```bash
curl -XPOST -u username:password -v -H "Content-Type: application/json" -d  '{"vault":"20170913T1114", "dbs":["db1","db2"]}' localhost:8080/restore
```

If you need to copy a database, you can use the `changeDbName` arg in JSON.

An example is given below:

```bash
curl -XPOST -u username:password -v -H "Content-Type: application/json" -d  '{"vault":"20170913T1114", "dbs":["db1","db2","db3""], "changeDbNames":{"db1":"new_db1_name","db2":"new_db2_name"}}' localhost:8080/restore
```

This will save `db1` and `db2` as they are on a DB server, and restore `db1` and `db2` into new (or existing)
databases called `new_db1_name` and `new_db2_name`. Database `db3` will be rewritten,
because it's not in `changeDbNames` list.

To run the full recovery, you need to set `enable_full_restore` property to `true` in backup daemon
configuration file or set it via environment variable `ENABLE_FULL_RESTORE`.

An example is given below:

```bash
curl -XPOST -u username:password -v -H "Content-Type: application/json" -d  '{"vault":"20170913T1114"}' localhost:8080/restore
```

Example restore from backup with timestamp specified:

```bash
curl -XPOST -u username:password -v -H "Content-Type: application/json" -d  '{"ts":"1689762600000"}' localhost:8080/restore
```

Example restore from incremental backup:

```bash
curl -XPOST -u username:password -v -H "Content-Type: application/json" -d  '{"vault":"20170913T1114"}' localhost:8080/incremental/restore
```

Example restore from backup that is stored on NFS:

```bash
curl -XPOST -u username:password -v -H "Content-Type: application/json" -d '{"externalBackupPath": "YYYYMMDDHHmmSS/mongo"}' localhost:8080/restore
```

#### Run External Restore (managed database)

To support resotre of managed database the following contract can be used:

```bash
curl -u <username>:<passwoed> -XPOST localhost:8080/external/restore -d '{"<custom_var_key1>":"<custom_var_value1>", "<custom_var_key2>":"<custom_var_value2>"}' -H "Content-Type: application/json"
```

* custom variables are used to support various parameters options for different managed DB providers
* the endpoint returns an ID of the restore operation and its status can be tracked as regular restore
* this endpoint only works if `enable_full_restore` is set to `true`

#### Get Backup/Recovery Status

You will receive Http responses: `200` for `OK`, `206` for `Still in process` and `500` for `NOT OK`.
Use the following command to get recovery status:

For full backups:

```bash
curl -XGET localhost:8080/jobstatus/<task_id>
```

or

```bash
curl -XGET localhost:8080/jobstatus/<vault_name>
```

For incremental backups:

```bash
curl -XGET localhost:8080/incremental/jobstatus/<task_id>
```

or

```bash
curl -XGET localhost:8080/incremental/jobstatus/<vault_name>
```

Also you will receive a JSON string as plain-text with the following information:

* `status`: Successful/Queued/Processing/Failed
* `message`: Optional field, only if error, contains description of error
* `vault`: vault name to use in recovery,
* `type`: backup/restore
* `err`: None if no error, last 5 lines of log if status=Failed
* `task_id`: task_id of the task

An example is given below:

```json
{"status": "Successful", "vault": "20170927T1122", "type": "backup", "err": "None", "task_id": "a592eeb6-abac-4d98-b638-75a820e333b1"}
```

#### List Backups

To list backups, use the following command:

For full backups:

```bash
curl -XGET localhost:8080/listbackups
```

For incremental backups:

```bash
curl -XGET localhost:8080/incremental/listbackups
```

This command will return a json list of backup names.

#### Find Backup

To find the backup with timestamp equal or newer than specified, use the following command:

For full backups:

```bash
curl -XGET -u username:password -v -H "Content-Type: application/json" -d  '{"ts":"1689762600000"}' localhost:8080/find
```

For incremental backups:

```bash
curl -XGET -u username:password -v -H "Content-Type: application/json" -d  '{"ts":"1689762600000"}' localhost:8080/incremental/find
```

This command will return a JSON string with stats about particular backup or the first backup newer that specified timestamp:

* `ts`: UNIX timestamp of backup
* `spent_time`: time spent on backup (in ms)
* `db_list`: List of backed up databases
* `id`: vault name
* `size`: Size of backup in bytes
* `evictable`: whether backup is evictable
* `locked`: whether backup is locked (either process isn't finished, or it failed somehow)
* `exit_code`: exit code of backup script
* `failed`: whether backup failed or not
* `valid`: is backup valid or not
* `is_granular`: Whether the backup is granular
* `sharded`: Whether the backup is sharded
* `canceled`: Whether the backup request canceled
* `custom_vars`: Custom variables with values that were used in backup preparation.
  It is specified if `.custom_vars` file exists in backup.

An example is given below:

```json
{"is_granular": false, "db_list": "full backup", "id": "20220113T230000", "failed": false, "locked": false, "sharded": false, "canceled": false, "ts": 1642114800000, "exit_code": 0, "spent_time": "9312ms", "size": "25283b", "valid": true, "evictable": true, "custom_vars": {"mode": "hierarchical"}}
```

#### Get Backup Information

To get the backup information, use the following command:

For full backups:

```shell
curl -XGET localhost:8080/listbackups/<vault_id>
```

For incremental backups:

```bash
curl -XGET localhost:8080/incremental/listbackups/<vault_id>
```

This command will return a JSON string with stats about particular backup:

* `ts`: UNIX timestamp of backup
* `spent_time`: time spent on backup (in ms)
* `db_list`: List of backed up databases
* `id`: vault name
* `size`: Size of backup in bytes
* `evictable`: whether backup is evictable
* `locked`: whether backup is locked (either process isn't finished, or it failed somehow)
* `exit_code`: exit code of backup script
* `failed`: whether backup failed or not
* `valid`: is backup valid or not
* `is_granular`: Whether the backup is granular
* `sharded`: Whether the backup is sharded
* `canceled`: Whether the backup request canceled
* `custom_vars`: Custom variables with values that were used in backup preparation.
  It is specified if `.custom_vars` file exists in backup.

An example is given below (json was formatted):

```json
{
  "is_granular": false,
  "db_list": "full backup",
  "id": "20220113T230000",
  "failed": false,
  "locked": false,
  "sharded": false,
  "canceled": false,
  "ts": 1642114800000,
  "exit_code": 0,
  "spent_time": "9312ms",
  "size": "25283b",
  "valid": true,
  "evictable": true,
  "custom_vars": {
    "mode": "hierarchical"
  }
}
```

#### Upload/Download API

To get backup archive, use the following command:

For full and granular backups:

```bash
curl -XGET localhost:8080/backup/<backup_id>
```

For incremental backups:

```bash
curl -XGET localhost:8080/incremental/backup/<backup_id>
```

This command will return a status 200 OK and archive with current backup that was specified in backup_id.

To upload backup archive, use the following command:

```bash
curl -XPOST 'http://localhost:8080/restore/backup' --form 'type="<type>"' --form 'allow_overwriting="<allow_overwriting>"' --form 'file=@"<path_to_file>"' 
```

Where:

* `type` is type of backup (granular or full)
*  `allow_overwriting` if `True` then existing backup with this id will be deleted
*  `path_to_file` is the path to archive with backup. Archive name will be used as backup name.

If the backup was successfully loaded, then the 200 status will return.

**Note** This functionality does not support S3 storages.

### Termination API

To terminate running backup procedure use following command:

```bash
curl -XGET localhost:8080/terminate/20220921T103159
```

You may specify externalBackupPath if it is used for the current backup.

```bash
curl -XPOST -H "Content-Type: application/json" -d '{"externalBackupPath": "/clickhouse/backups"}' localhost:8080/terminate/20220921T103159
```

This command will return a status 200 OK if termination is done correctly.
Also, it may return 406 Not Acceptable if provided backup has already been canceled.

## CLI Usage

Backup Daemon image has out of the box CLI `bdcli` which proxies requests to REST API.

It can be used for manual executions or integrations require in-pod execution like `Velero` hooks.

```shell
usage: bdcli [-h]
                {backup,b,restore,r,list,l,describe,get,d,status,s,evict,e}
                ...

Backup Daemon CLI is a shell client for Backup Daemon REST API.

optional arguments:
  -h, --help            show this help message and exit

commands:
  {backup,b,restore,r,list,l,describe,get,d,status,s,evict,e}
    backup (b)          Perform backup.
    restore (r)         Perform restore. Must be used with backup identifier
    list (l)            List backups
    describe (get, d)   Describe backup. Must be used with backup identifier `describe <backup_id>` or `describe <timestamp>`
    status (s)          Describe status of operation. Must be used with job identifier `status <job_id>`
    evict (e)           Evict backup. Can be used with backup identifier `evict <backup_id>`. If used without parameters all evictable backups will be removed.

optional arguments:
  -h, --help            show this help message and exit
  --username USERNAME, -u USERNAME
                        The username of Backup Daemon API. By default the value of 'BACKUP_DAEMON_API_CREDENTIALS_USERNAME' environment variable is used.
  --password PASSWORD, -p PASSWORD
                        The password of Backup Daemon API. By default the value of 'BACKUP_DAEMON_API_CREDENTIALS_PASSWORD' environment variable is used.
  --host HOST           The url address of Backup Daemon REST API. By default the local address is used `http(s)://localhost:8080(8443)`.
  --verify VERIFY       The path to CA certificate to verify HTTPS connection or `false` to disable it. By default the value of `{CERTS_PATH}/ca.crt` is used.
  --incremental, -i     Use incremental API for execution commands. Default false.
  --verbose, -v         Verbose output of executing commands. By default it responses with final output of Backup Daemon API only.
  --wait, -w            Wait for command execution for async commands like `backup` or `restore`. By default all commands are asynchronous.
  --timeout TIMEOUT, -t TIMEOUT
                        Timeout for commands execution (in seconds). By default: 60.
  --dbs DBS [DBS ...]   Databases to perform operation delimited by space. If not specified - all databases are used.
  --properties PROPERTIES [PROPERTIES ...]
                        Additional properties as key=value.
  --input INPUT, --in INPUT
                        Specify the path to the file with input data for command
  --output OUTPUT, --out OUTPUT
                        Specify the path to the file with output data of command

Examples:

bdcli backup
bdcli restore 20230303T101010
bdcli restore 1692321321312 --dbs database1 database2 --properties cluster=aws mode=all --wait
bdcli describe 20230303T101010
bdcli status 66a0f51b-e6ac-4e89-b2c7-48774ed05a7c
```
