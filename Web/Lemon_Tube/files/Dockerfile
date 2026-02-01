FROM python:3.9-slim

WORKDIR /app

# Install Chrome, dependencies for Selenium, and Supervisor
RUN apt-get update && apt-get install -y \
    chromium \
    chromium-driver \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Copy supervisor configuration
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 5005

# Default environment variable for flag (can be overridden by CTFd)
ENV FLAG="L3m0nctf{default_docker_flag}"

# Start via entrypoint (writes FLAG to flag.txt, then starts supervisord)
CMD ["/entrypoint.sh"]
