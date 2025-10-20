# systemd Service Unit

This service file manages the gateway via the CLI daemon interface.

## Installation

1. Create an operating system user for the gateway (optional but recommended):
   ```bash
   sudo useradd --system --home /etc/apigw --shell /usr/sbin/nologin apigw
   ```
2. Place your configuration at `/etc/apigw/gateway.yaml` and ensure the
   directory is readable by the `apigw` user.
3. Copy the binary (or unpack a release artifact) to `/usr/local/bin/apigw`.
4. Copy `deploy/systemd/apigw.service` to `/etc/systemd/system/apigw.service`.
5. Optional: create `/etc/default/apigw` to inject environment variables, e.g.:
   ```
   TRADE_API_URL=https://trade.example.com
   TASK_API_URL=https://task.example.com
   JWT_SECRET=replace-me
   ```
6. Reload systemd and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now apigw.service
   ```

Logs are written to `/var/log/apigw/apigw.log` per the unit configuration. The
PID file is stored in `/run/apigw.pid` and is managed by the CLI daemon.

Adjust paths or user/group assignments to match your environment.
