# Auto-deploy

Cron on the server runs [autodeploy.sh](autodeploy.sh) every 5 minutes. When
`main` has a new commit that passed CI (`Lint & Test`), it fast-forwards
`/opt/SignalSage` and runs `docker compose up -d --build`. Nothing on GitHub
needs access to the server.

## Install (once, on the server)

The production host is Alpine (busybox crond, no systemd or bash):

```sh
chmod +x /opt/SignalSage/deploy/autodeploy.sh
echo '*/5 * * * * /opt/SignalSage/deploy/autodeploy.sh >> /var/log/signalsage-autodeploy.log 2>&1' >> /etc/crontabs/root
```

## Use

- Log: `tail -n 50 /var/log/signalsage-autodeploy.log`
- Deploy now: `/opt/SignalSage/deploy/autodeploy.sh`
- Pause: comment out the line in `/etc/crontabs/root`

Keep server-only settings in the gitignored `config/config.local.yaml` and
`.env`. Editing tracked files on the server makes the fast-forward fail
(the log says so) until the edit is reverted.

Switching the LLM backend (`COMPOSE_PROFILES`) still needs a manual
`docker compose down && docker compose up -d --build`.
