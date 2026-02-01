FROM python:3.9-slim

WORKDIR /app

# Install openssl for key generation
RUN apt-get update && \
    apt-get install -y openssl && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Generate keys as required by server.py
RUN openssl genrsa -out private.pem 2048 && \
    openssl rsa -in private.pem -pubout -out public.pem && \
    openssl req -new -x509 -key private.pem -out cert.pem -days 365 -subj '/C=US/ST=NeonState/L=NeonCity/O=NeonVault/OU=neon_root_key/CN=auth.neonvault.local'

# Create a non-root user and give ownership of app files
RUN useradd -m ctf && \
    chown -R ctf:ctf /app
USER ctf

EXPOSE 5001

# Default environment variable for flag (can be overridden)
ENV FLAG="L3m0nctf{default_docker_flag}"

CMD ["python", "server.py"]
