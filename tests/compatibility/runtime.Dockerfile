# Trusted synthetic-test dependencies, provisioned explicitly by the test harness.
FROM python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir 'Flask>=3,<4'
