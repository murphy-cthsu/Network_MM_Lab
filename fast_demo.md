## Preparation

Make sure to modify the server URL in `attester/agent.py`

## One-time enrollment / after a key rotation

```sh
# laptop
python3 verifier/make_policy_key.py            # --force to rotate

# scp verifier/policy_pub.pem to RPI

# pi
cp verifier/policy_pub.pem attester/policy_pub.pem   # enroll the new public

### AK Genearation : run if you don't have one or you want a new one ###

# pi
.venv/bin/python attester/provision.py               

# scp verifier/ak_pub.pem verifier/ak.pub to laptop

### AK Genearation Done ###

.venv/bin/python attester/seal.py                    # re-seal to the new key
```

## Server and DEMO Steps

```bash
# on RPI
dev/prepare_demo_p2.sh
# on laptop
scp team2@[RPI_IP]:/home/team2/Network_MM_Lab/verifier/allowlist.json verifier/allowlist.json # copy allowlist for server

# on RPI
sudo .venv/bin/python attester/payload/camera_stream.py --host 0.0.0.0 --port 8001 # activate camera

# on laptop
python verifier/server.py --host 0.0.0.0 --port 5000 --camera-url http:/[RPI_IP]:8001 # activate server

# press buttoms on UI to identify the good person

# on (another) laptop: ssh to RPI
/tamper/swap_model.sh

# press buttoms, show compromised

# on (another) laptop: ssh to RPI
/tamper/restore_model.sh

# press buttoms, show still compromised

```