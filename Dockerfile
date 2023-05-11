# Build a virtual env and collect static files
FROM public.ecr.aws/docker/library/python:3.11 AS builder
ARG REQUIREMENTS_FILE
WORKDIR /app
RUN python -m venv /venv
ENV PATH="/venv/bin:$PATH"
COPY requirements ./requirements
RUN pip install -U pip && \
  pip install --no-cache-dir -r ${REQUIREMENTS_FILE:-requirements/dev.txt}
COPY . .
RUN python manage.py collectstatic --noinput

# Build a final image that only includes run-time dependencies
FROM public.ecr.aws/docker/library/python:3.11 AS builder-runtime
LABEL maintainer="rob@deep-ink.ventures"
WORKDIR /usr/src/app
RUN useradd app
RUN chown -R app:app /usr/src/app
COPY --from=builder --chown=app:app /venv /venv
COPY --from=builder --chown=app:app /app .
ENV PATH="/venv/bin:$PATH"
USER app
ENTRYPOINT ["./entrypoint.sh"]
