FROM python:3.12.11-alpine3.22

ARG G2P_REF=v2.0.0

RUN apk add --no-cache --virtual .build-deps gcc libc-dev linux-headers make \
 && apk add --no-cache bash git gettext libpq-dev libmagic

WORKDIR /app

COPY . /app/src

RUN python3 -m pip install  \
    git+https://github.com/openg2p/openg2p-fastapi-common@1.1\#subdirectory=openg2p-fastapi-common \
    git+https://github.com/openg2p/openg2p-fastapi-common@1.1\#subdirectory=openg2p-fastapi-auth \
    ./src


RUN apk del --no-network .build-deps

ENV PYTHONUNBUFFERED=1
ENV PORTAL_NO_OF_WORKERS=2
ENV PORTAL_HOST=0.0.0.0
ENV PORTAL_PORT=8000
ENV PORTAL_ORKER_TYPE=gunicorn

CMD ["sh", "-c", "python3 src/main.py migrate; gunicorn 'src.main:app' --workers ${PORTAL_NO_OF_WORKERS} --worker-class uvicorn.workers.UvicornWorker --bind ${PORTAL_HOST}:${PORTAL_PORT}"]