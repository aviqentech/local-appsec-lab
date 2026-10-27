# Explicit trusted test/runtime provisioning; no repository lifecycle code runs here.
FROM mcr.microsoft.com/playwright/python:v1.64.1-noble
RUN python -m pip install --no-cache-dir playwright==1.64.1 'Flask>=3,<4' 'psycopg[binary]>=3,<4' \
    && apt-get update && apt-get install -y --no-install-recommends nodejs npm \
    && rm -rf /var/lib/apt/lists/*
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
