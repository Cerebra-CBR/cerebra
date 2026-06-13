# Cereblix on Hive OS

A ready-made **Custom Miner** package so a Hive OS rig can CPU-mine CRB from a
Flight Sheet (auto-start, survives reboot, hashrate shown in the dashboard).

## Install (Flight Sheet)

1. **Wallets → Add Wallet**: coin `Custom`, paste your CRB address (`crb1…`).
   No wallet yet? Make one at https://cereblix.com/wallet/
2. **Flight Sheets → Create**: select the Custom wallet, then under **Miner**
   choose **Custom** and click **Setup Miner Config**:
   - **Miner name / Installation URL**:
     `https://github.com/Cerebra-CBR/cereblix/releases/latest/download/cereblix-hiveos.tar.gz`
   - **Pool URL**: `https://cereblix.com/pool/api`
     (RU/CIS, if cereblix.com is slow or blocked: `https://ru.cereblix.com/pool/api`)
   - **Extra config arguments** (optional): e.g. `-threads 6`
     (defaults to all cores; on a GPU rig leave a couple free)
3. Apply the Flight Sheet to the rig. Done — it downloads, starts, and reports
   hashrate + accepted shares to the dashboard.

Pool payouts arrive automatically once your balance matures (~100 blocks).

## Quick alternative (no package)

Just run the standalone Linux binary from the Hive Shell:

```bash
cd /home/user
wget https://github.com/Cerebra-CBR/cereblix/releases/latest/download/cereblix-miner-linux-amd64 -O cereblix-miner
chmod +x cereblix-miner
screen -dmS crb ./cereblix-miner -addr crb1YOUR_ADDRESS -node https://cereblix.com/pool/api
```

## Files in this package

| file | role |
|------|------|
| `h-manifest.conf` | name/version + config & log paths |
| `h-config.sh` | turns Flight Sheet fields (wallet, pool URL, extra args) into miner flags |
| `h-run.sh` | launches `cereblix-miner`, tees output to the log |
| `stats.sh` | parses the log, reports `khs` + `stats` JSON to Hive |
| `cereblix-miner` | the Linux x86_64 CPU miner binary (bundled) |
