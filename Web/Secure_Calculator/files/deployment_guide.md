# Deployment Guide for CTF Challenge

This guide explains how to deploy the "Command Injection" challenge to a remote server (e.g., a VPS, CTF platform server).

## Prerequisites

- A remote server (Linux recommended, e.g., Ubuntu).
- SSH access to the server.
- `docker` and `docker-compose` installed on the server.

## Steps

### 1. Transfer Files to Server

You need to copy the challenge files to your server. You can use `scp` or `rsync`.

Run this command from your **local machine** (replace `user@your-server-ip` with your actual server details):

```bash
# Copy the entire directory
scp -r /home/akvnn/Downloads/l3mon_ctf/command\ ijection/ user@your-server-ip:~/ctf_challenge
```

### 2. Connect to the Server

SSH into your server:

```bash
ssh user@your-server-ip
cd ~/ctf_challenge
```

### 3. Start the Challenge

Run the following command to build and start the container:

```bash
# You might need sudo depending on your docker setup
sudo docker compose up -d --build
# OR if you have the older standalone version:
# sudo docker-compose up -d --build
```

- `-d`: Runs in detached mode (in the background).
- `--build`: Forces a rebuild of the image to ensure latest changes are applied.

### 4. Verify Deployment

Check if the container is running:

```bash
docker ps
```

You should see `ctf_challenge_container` listed and port `0.0.0.0:5000->5000/tcp` mapped.

### 5. Access the Challenge

Open your browser and navigate to:

```
http://your-server-ip:5000
```

## Troubleshooting

- **Port Conflict**: If port 5000 is already in use, edit `docker-compose.yml` and change the ports section (e.g., `"8080:5000"` to expose it on port 8080).
- **Logs**: To see application logs, run `docker-compose logs -f`.
- **Stop**: To stop the challenge, run `docker-compose down`.
