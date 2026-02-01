# Deployment Instructions for L3mon Web CVE

## Prerequisites
- Docker
- Docker Compose

## Files to Upload
Upload the entire `l3mon_web_cve` directory to your CTF server. Ensure the following files are present:
- `app.py`
- `bot.py`
- `Dockerfile`
- `docker-compose.yml`
- `requirements.txt`
- `supervisord.conf`
- `flag.txt`
- `templates/` (directory)
- `static/` (directory)

## How to Run
1.  Navigate to the directory:
    ```bash
    cd l3mon_web_cve
    ```
2.  Build and start the container:
    ```bash
    docker-compose up -d --build
    ```

## Configuration
You can modify the `docker-compose.yml` file to change:
- `ADMIN_TOKEN`: The secret token required for admin access.
- `PORT`: The external port (default is 5005).

## Verification
- Access the challenge at `http://<server-ip>:5005`.
- Ensure the bot is running by checking logs:
    ```bash
    docker-compose logs -f
    ```
