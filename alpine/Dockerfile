FROM python:3.10-alpine

ENV BACKUP_DAEMON_HOME=/opt/backup
ENV S3_CERT_PATH_INTERNAL=/s3CertInternal

ARG PY_APSW_VER="3.40.1.0"
ARG PIP="25.3"
ARG SETUPTOOLS="80.9.0"
ARG TMP_DIR="/tmp"

COPY requirements.txt ${BACKUP_DAEMON_HOME}/

RUN set -x \
    && pip3 install --upgrade pip==${PIP} setuptools==${SETUPTOOLS} \
    && rm -rf /var/cache/apk/* \
    && apk add --no-cache curl sqlite sqlite-dev build-base \
    && wget \
        --no-check-certificate \
        -nv \
        -O ${TMP_DIR}/apsw-${PY_APSW_VER}.zip \
        "https://github.com/rogerbinns/apsw/releases/download/${PY_APSW_VER}/apsw-${PY_APSW_VER}.zip" \
    && unzip ${TMP_DIR}/apsw-${PY_APSW_VER}.zip && cd ./apsw-${PY_APSW_VER}/ && python setup.py install \
    && rm -rf ${TMP_DIR}/* \
    && pip3 install -r ${BACKUP_DAEMON_HOME}/requirements.txt \
    && apk del build-base

COPY src tests ${BACKUP_DAEMON_HOME}/
RUN python3 -m unittest discover -s ${BACKUP_DAEMON_HOME} -p "*_tests.py"

COPY tools/bdcli.py /usr/bin/bdcli

RUN chmod +x /usr/bin/bdcli
RUN chmod 777 /var/log

RUN mkdir -p ${S3_CERT_PATH_INTERNAL} \
    && chmod 777 ${S3_CERT_PATH_INTERNAL}

VOLUME /backup-storage

CMD ["python3", "/opt/backup/backup-daemon.py"]