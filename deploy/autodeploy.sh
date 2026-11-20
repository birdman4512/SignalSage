#!/bin/sh
# Pull-based auto-deploy, run from cron every 5 minutes (see deploy/README.md).
# When origin/main has moved AND GitHub CI ("Lint & Test") passed for that
# commit, fast-forward the checkout and rebuild/restart the compose stack.
# POSIX sh: the server is Alpine (busybox ash, no bash).
set -eu

REPO_DIR="${REPO_DIR:-/opt/SignalSage}"
BRANCH="${BRANCH:-main}"
GITHUB_REPO="${GITHUB_REPO:-birdman4512/SignalSage}"
CHECK_NAME="${CHECK_NAME:-Lint%20%26%20Test}"   # URL-encoded "Lint & Test"

log() { echo "$(date '+%F %T') $*"; }

cd "$REPO_DIR"
exec 9>/run/lock/signalsage-autodeploy.lock
flock -n 9 || exit 0

git fetch --quiet origin "$BRANCH"
local_sha=$(git rev-parse HEAD)
remote_sha=$(git rev-parse "origin/$BRANCH")
[ "$local_sha" = "$remote_sha" ] && exit 0
short=$(git rev-parse --short "$remote_sha")

# Only deploy commits CI has passed. Public repo, so no token is needed; the
# API is only called when there is a new commit.
if ! runs=$(curl -fsS -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/$GITHUB_REPO/commits/$remote_sha/check-runs?check_name=$CHECK_NAME"); then
  log "Could not read CI status for $short; retrying later"
  exit 0
fi
if ! printf '%s' "$runs" | grep -q '"conclusion": *"success"'; then
  if printf '%s' "$runs" | grep -qE '"conclusion": *"(failure|cancelled|timed_out)"'; then
    log "CI failed for $short; not deploying"
  else
    log "CI not finished for $short; waiting"
  fi
  exit 0
fi

# A commit whose build failed is skipped until main moves on (or the marker is
# deleted), so a broken build isn't retried on a small VM every 5 minutes.
FAILED_MARKER="${FAILED_MARKER:-/var/tmp/signalsage-autodeploy.failed}"
if [ "$(cat "$FAILED_MARKER" 2>/dev/null || true)" = "$remote_sha" ]; then
  exit 0
fi

log "Deploying $(git rev-parse --short HEAD) -> $short"
git merge --ff-only --quiet "origin/$BRANCH"
# Build while the old container keeps serving. On failure, step the checkout
# back so the running code and the checkout agree.
if ! docker compose build; then
  git reset --hard --quiet "$local_sha"
  echo "$remote_sha" > "$FAILED_MARKER"
  log "Build failed for $short; still running $(git rev-parse --short HEAD). Delete $FAILED_MARKER to retry."
  exit 1
fi
# No `down`: the bot is replaced in place. If that fails (e.g. a renamed
# compose service whose old container still holds container_name), remove the
# project's containers, orphans included, and start again.
if ! docker compose up -d --remove-orphans; then
  log "Replacing the container failed; removing old containers and retrying"
  docker compose down --remove-orphans
  docker compose up -d --remove-orphans
fi
rm -f "$FAILED_MARKER"
# Prune old images and build cache so a small VM disk doesn't fill up.
docker image prune -f >/dev/null
docker builder prune -f --filter until=168h >/dev/null
log "Deployed $(git log -1 --format='%h %s')"
