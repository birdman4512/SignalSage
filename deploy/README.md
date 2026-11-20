# Deploy

SignalSage runs as one Docker container. It needs only outbound internet, so it
fits on a free-tier VM. Production is a **Google Cloud e2-micro** (free tier:
1 GB RAM, 30 GB standard disk, `us-central1`/`us-west1`/`us-east1` only).

## New VM (Debian 12, GCP free tier)

```sh
# Cloud Shell
gcloud compute instances create signalsage --zone=us-central1-a \
  --machine-type=e2-micro --image-family=debian-12 --image-project=debian-cloud \
  --boot-disk-size=30GB --boot-disk-type=pd-standard   # pd-standard: "balanced" is billed

# On the VM: 2 GB swap (the image build needs it), Docker, the code
sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
sudo apt-get update && sudo apt-get install -y git curl
curl -fsSL https://get.docker.com | sudo sh
sudo git clone https://github.com/birdman4512/SignalSage.git /opt/SignalSage
cd /opt/SignalSage
sudo cp .env.example .env && sudo chmod 600 .env   # fill in tokens + GEMINI_API_KEY
sudo mkdir -p data && sudo chown -R 10001:10001 data
sudo docker compose up -d --build
```

Set a billing budget alert (e.g. $1) on the project. The Gemini key must come
from a *different* project that has no billing, or it is on the paid tier.

Some sites block cloud-provider IP ranges (cyber.gov.au's feeds do). Such
sources fail from the VM even though they work from home.

## Auto-deploy

Cron runs [autodeploy.sh](autodeploy.sh) every 5 minutes. When `main` has a new
commit that passed CI (`Lint & Test`), it fast-forwards `/opt/SignalSage`, runs
`docker compose up -d --build`, and prunes old images and build cache. Nothing on
GitHub needs access to the server.

```sh
sudo chmod +x /opt/SignalSage/deploy/autodeploy.sh
# Debian/Ubuntu (cron.d needs the user field):
echo '*/5 * * * * root /opt/SignalSage/deploy/autodeploy.sh >> /var/log/signalsage-autodeploy.log 2>&1' \
  | sudo tee /etc/cron.d/signalsage
# Alpine (busybox crond):
#   echo '*/5 * * * * /opt/SignalSage/deploy/autodeploy.sh >> /var/log/signalsage-autodeploy.log 2>&1' >> /etc/crontabs/root
#   rc-service crond restart
```

- Log: `tail -n 50 /var/log/signalsage-autodeploy.log`
- Deploy now: `sudo /opt/SignalSage/deploy/autodeploy.sh`
- Pause: comment out the cron line

If a build fails after the fast-forward, the old container keeps running but
the next cron run sees nothing new. Fix the cause, then run
`sudo docker compose up -d --build` by hand.

Keep server-only settings in the gitignored `.env`, `config/config.local.yaml`
and `config/digests/*.local.yaml`. Editing tracked files on the server makes the
fast-forward fail (the log says so) until the edit is reverted.
