FROM python:3.12.11-alpine3.22

# Build args for non-root user
ARG container_user=openg2p
ARG container_user_group=openg2p
ARG container_user_uid=1001
ARG container_user_gid=1001

# Create group and user
RUN groupadd -g ${container_user_gid} ${container_user_group} \
  && useradd -mN -u ${container_user_uid} -G ${container_user_group} -s /bin/bash ${container_user}

WORKDIR /app

# System packages
RUN apk add --no-cache --virtual .build-deps gcc libc-dev linux-headers make \
 && apk add --no-cache bash git gettext libpq-dev libmagic

# Ensure ownership
RUN chown -R ${container_user}:${container_user_group} /app

# Copy source
ADD --chown=${container_user}:${container_user_group} . /app/src
ADD --chown=${container_user}:${container_user_group} main.py /app

# Python dependencies
RUN python3 -m pip install \
  git+https://github.com/openg2p/openg2p-fastapi-common@v1.1.2#subdirectory=openg2p-fastapi-common \
  git+https://github.com/openg2p/openg2p-fastapi-common@v1.1.2#subdirectory=openg2p-fastapi-auth \
  ./src

USER ${container_user}

# Cleanup build dependencies
RUN apk del --no-network .build-deps

ENV PYTHONUNBUFFERED=1
ENV PORTAL_HOST=0.0.0.0
ENV PORTAL_PORT=8000
ENV PORTAL_NO_OF_WORKERS=8
ENV PORTAL_WORKER_TYPE=gunicorn


# Run DB migrations, then start the API
CMD python3 main.py migrate; \
    gunicorn "main:app" --workers ${PORTAL_NO_OF_WORKERS} --worker-class uvicorn.workers.UvicornWorker --bind ${PORTAL_HOST}:${PORTAL_PORT}
