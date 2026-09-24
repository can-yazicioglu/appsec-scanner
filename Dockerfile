FROM python:3.12-slim
WORKDIR /app
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
COPY pyproject.toml ./
COPY appsec ./appsec
RUN pip install --no-cache-dir '.[browser]' && python -m playwright install --with-deps chromium
RUN useradd --create-home scanner && mkdir /data && chown scanner:scanner /data
USER scanner
ENTRYPOINT ["appsec", "--db", "/data/appsec.db"]
CMD ["--help"]
