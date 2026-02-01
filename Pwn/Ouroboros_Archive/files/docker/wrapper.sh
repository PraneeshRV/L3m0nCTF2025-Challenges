#!/bin/bash
# Netcat wrapper script for Docker container

set -e

# Create isolated workspace
WORKSPACE="/tmp/chal_$$"
mkdir -p "$WORKSPACE/sandbox"
cd "$WORKSPACE"

echo "=== Ouroboros Archive Unpacker ==="
echo "Send your ZIP file (base64 encoded):"

# Read ZIP with timeout (30 seconds)
read -t 30 -r b64_zip || {
    echo "Error: Timeout"
    exit 1
}

# Validate input size
if [ ${#b64_zip} -gt 100000 ]; then
    echo "Error: ZIP too large (max 100KB base64)"
    exit 1
fi

# Decode ZIP
echo "$b64_zip" | base64 -d > input.zip 2>/dev/null || {
    echo "Error: Invalid base64"
    exit 1
}

# Check ZIP is not too large
ZIP_SIZE=$(stat -f%z input.zip 2>/dev/null || stat -c%s input.zip)
if [ "$ZIP_SIZE" -gt 50000 ]; then
    echo "Error: ZIP too large"
    exit 1
fi

# Run unpacker
/challenge/unzipper input.zip

# Cleanup
cd /
rm -rf "$WORKSPACE"
