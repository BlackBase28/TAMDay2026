FROM registry.access.redhat.com/ubi9/python-311:latest

WORKDIR /opt/app-root/src
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=1001:0 . .
RUN mkdir -p /data && chown -R 1001:0 /data /opt/app-root/src && chmod -R g=u /data /opt/app-root/src

USER 1001
ENV DATABASE_PATH=/data/kernel_cve.db \
    PYTHONUNBUFFERED=1 \
    PORT=8000
EXPOSE 8000

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "4", "--timeout", "60", "--access-logfile", "-", "--error-logfile", "-", "wsgi:app"]
