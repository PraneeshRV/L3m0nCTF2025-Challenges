FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Copy and make entrypoint executable
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Default FLAG (can be overridden by CTFd)
ENV FLAG="L3m0nCTF{4g3n7_45_m15510n_c0mpl373d}"

# Expose port
EXPOSE 5000

# Run as root for file upload/execution and flag access
ENTRYPOINT ["/entrypoint.sh"]
