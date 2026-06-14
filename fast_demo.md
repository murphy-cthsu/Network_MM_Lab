```bash
# on RPI
dev/prepare_demo_p2.sh
# on laptop
scp team2@172.20.10.3:/home/team2/Network_MM_Lab/verifier/allowlist.json verifier/allowlist.json # copy allowlist for server
# on RPI
sudo .venv/bin/python attester/payload/camera_stream.py --host 0.0.0.0 --port 8001 # activate camera
# on laptop
python verifier/server.py --host 0.0.0.0 --port 5000 --camera-url http://172.20.10.3:8001 # activate server, the url is the ip address of RPI

# press buttoms on UI to identify the good person

# on (another) laptop: ssh to RPI
/tamper/swap_model.sh

# press buttoms, show compromised

# on (another) laptop: ssh to RPI
/tamper/restore_model.sh

# press buttoms, show still compromised

```