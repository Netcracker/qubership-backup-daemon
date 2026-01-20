FROM python:3.10-alpine

ENV BACKUP_DAEMON_HOME=/opt/backup
ENV S3_CERT_PATH_INTERNAL=/s3CertInternal

ARG PY_APSW_VER="3.40.1.0"
ARG PIP="25.3"
ARG SETUPTOOLS="80.9.0"
ARG TMP_DIR="/tmp"

COPY requirements.txt ${BACKUP_DAEMON_HOME}/

# hadolint ignore=DL3003,DL3018
RUN set -x \
    && pip3 install --no-cache-dir --upgrade pip==${PIP} setuptools==${SETUPTOOLS} \
    && rm -rf /var/cache/apk/* \
    && apk add --no-cache curl sqlite sqlite-dev build-base ca-certificates \
    && wget \
        -nv \
        -O ${TMP_DIR}/apsw-${PY_APSW_VER}.zip \
        "https://github.com/rogerbinns/apsw/releases/download/${PY_APSW_VER}/apsw-${PY_APSW_VER}.zip" \
    && unzip ${TMP_DIR}/apsw-${PY_APSW_VER}.zip -d ${TMP_DIR} \
    && cd ${TMP_DIR}/apsw-${PY_APSW_VER} \
    && python setup.py install \
    && rm -rf "${TMP_DIR:?}/"* \
    && pip3 install --no-cache-dir -r ${BACKUP_DAEMON_HOME}/requirements.txt \
    && apk del build-base

RUN addgroup -S backup && adduser -S backup -G backup

COPY src tests ${BACKUP_DAEMON_HOME}/
RUN python3 -m unittest discover -s ${BACKUP_DAEMON_HOME} -p "*_tests.py"

COPY tools/bdcli.py /usr/bin/bdcli

RUN chmod +x /usr/bin/bdcli \
    && chmod 770 /var/log \
    && mkdir -p ${S3_CERT_PATH_INTERNAL} \
    && chmod 770 ${S3_CERT_PATH_INTERNAL} \
    && chown -R backup:backup ${BACKUP_DAEMON_HOME} ${S3_CERT_PATH_INTERNAL} /var/log

USER backup

VOLUME /backup-storage

CMD ["python3", "/opt/backup/backup-daemon.py"]
