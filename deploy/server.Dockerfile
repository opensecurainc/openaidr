FROM python:3.12-slim AS builder
WORKDIR /src
COPY pyproject.toml setup.py MANIFEST.in README.md ./
COPY src/ src/
# The OpenAIDR SDK and shared contract wheels are vendored under dependencies/.
COPY dependencies/api-runtime/ /vendored/
ARG OPENAIDR_BUILD_COMMIT
ARG OPENAIDR_COMMIT_TIMESTAMP
RUN pip wheel --no-cache-dir --find-links /vendored --wheel-dir /wheels /vendored/*.whl ".[server]"
FROM python:3.12-slim
COPY --from=builder /wheels /wheels
COPY scripts/local_bootstrap.py /usr/local/bin/openaidr-local-bootstrap
RUN pip install --no-cache-dir --no-index --find-links /wheels 'openaidr[server]' && rm -rf /wheels \
    && chmod 0755 /usr/local/bin/openaidr-local-bootstrap \
    && useradd --create-home --uid 10001 openaidr \
    && install -d -o openaidr -g openaidr /run/openaidr-tenant
USER openaidr
WORKDIR /home/openaidr
ENV OPENAIDR_LISTEN=0.0.0.0:8081
EXPOSE 8081
ENTRYPOINT ["openaidr-server"]
CMD ["serve"]
