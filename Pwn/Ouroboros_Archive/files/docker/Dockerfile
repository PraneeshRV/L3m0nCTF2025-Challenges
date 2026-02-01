FROM ubuntu:22.04

# Install build tools, runtime libraries, and socat for concurrent connections
RUN apt-get update && \
    apt-get install -y gcc socat libzip4 libzip-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy source and build inside container
COPY src/unzipper.c /tmp/unzipper.c
RUN mkdir -p /challenge && \
    gcc -o /challenge/unzipper /tmp/unzipper.c \
    -Wall -Wextra \
    -fstack-protector-all \
    -D_FORTIFY_SOURCE=2 \
    -lzip \
    -O2 && \
    strip --strip-all /challenge/unzipper && \
    rm /tmp/unzipper.c

# Copy wrapper script
COPY docker/wrapper.sh /challenge/wrapper.sh
RUN chmod 555 /challenge/unzipper /challenge/wrapper.sh

# Set SUID on unzipper
RUN chown root:root /challenge/unzipper && \
    chmod 4755 /challenge/unzipper

# Create working directory
RUN mkdir -p /tmp && chmod 1777 /tmp

# Expose port
EXPOSE 1337

# Use socat to handle multiple concurrent connections
# fork = spawn child process for each connection
# reuseaddr = allow quick restart
# max-children = limit concurrent connections to prevent DoS
CMD ["socat", "-T30", "TCP-LISTEN:1337,reuseaddr,fork,max-children=100", "EXEC:/challenge/wrapper.sh"]
