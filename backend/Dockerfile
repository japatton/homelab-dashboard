FROM python:3.12-slim AS deps

WORKDIR /app

# nmap is needed for live scans, curl for healthchecks, git for
# Claude-generated integrations fetch.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM deps AS runtime

WORKDIR /app

# Non-root user — required for `read_only: true` root filesystems and for
# defence-in-depth if something reaches code execution. UID/GID pinned so
# named-volume ownership is reproducible across rebuilds.
#
# NOTE on `/data` ownership for pre-existing deployments: the homelab-data
# volume was populated as root by the old image, so an in-place upgrade
# needs a one-time chown. We can't do it from the entrypoint (cap_drop:ALL
# strips CAP_CHOWN/CAP_SETUID and the container can't even gosu), so
# `deploy.sh` runs a privileged busybox sidecar to chown the volume
# before starting containers. See the volume-migration block there.
RUN groupadd -r --gid 1000 app \
    && useradd -r --uid 1000 -g app --shell /usr/sbin/nologin app \
    && mkdir -p /data /app/integrations \
    && chown -R app:app /data /app

COPY --chown=app:app . .

USER app

EXPOSE 8000

CMD ["uvicorn", "main:socket_app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
