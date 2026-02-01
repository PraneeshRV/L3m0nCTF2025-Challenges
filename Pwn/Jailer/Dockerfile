FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    socat \
    && rm -rf /var/lib/apt/lists/*

# Create challenge directory and jail
RUN mkdir -p /challenge /tmp/empty-jail

# Copy challenge binary and flag
COPY jailer /challenge/jailer
COPY flag.txt /flag.txt

RUN chmod 755 /challenge/jailer
RUN chmod 444 /flag.txt

# Set working directory
WORKDIR /challenge

# Expose the challenge port
EXPOSE 1338

# Wrapper script for socat - passes user input as command
RUN echo '#!/bin/bash\nread -p "Enter command: " cmd\n/challenge/jailer "$cmd"' > /challenge/run.sh && chmod +x /challenge/run.sh

# Run with socat
CMD ["socat", "TCP-LISTEN:1338,reuseaddr,fork", "EXEC:/challenge/run.sh,pty,stderr"]
