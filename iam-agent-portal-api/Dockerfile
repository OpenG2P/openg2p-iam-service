FROM python:3.12.11-alpine3.22

ARG IAM_REF=develop

RUN apk add --no-cache --virtual .build-deps gcc libc-dev linux-headers make \
 && apk add --no-cache bash git gettext libpq-dev libmagic

WORKDIR /app

# Core IAM dependencies from the openg2p-iam-service repo
RUN pip install --no-cache-dir openg2p-fastapi-common==1.1 \
    && pip install --no-cache-dir "git+https://github.com/openg2p/openg2p-iam-service@${IAM_REF}#subdirectory=iam-core" \
    && pip install --no-cache-dir "git+https://github.com/openg2p/openg2p-iam-service@${IAM_REF}#subdirectory=iam-agent-portal-api"

RUN apk del --no-network .build-deps

ENV PYTHONUNBUFFERED=1
ENV IAM_API_NO_OF_WORKERS=2
ENV IAM_API_HOST=0.0.0.0
ENV IAM_API_PORT=8000
ENV IAM_API_WORKER_TYPE=gunicorn

# Run DB migrations, then start Gunicorn with Uvicorn workers
CMD python3 -m iam_agent_portal_api.main migrate; \
    gunicorn "iam_agent_portal_api.main:app" --workers ${IAM_API_NO_OF_WORKERS} --worker-class uvicorn.workers.UvicornWorker --bind ${IAM_API_HOST}:${IAM_API_PORT}

