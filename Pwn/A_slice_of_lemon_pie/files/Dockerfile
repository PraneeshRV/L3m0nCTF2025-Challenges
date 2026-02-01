FROM ubuntu:22.04

RUN apt-get update && apt-get install -y socat

WORKDIR /app

# Copy the pre-compiled binary (same as distributed to participants)
COPY format_pie .
RUN chmod +x format_pie

# Create entrypoint script for dynamic flag
RUN echo '#!/bin/bash\n\
    if [ -n "$FLAG" ]; then\n\
    echo "$FLAG" > /app/flag.txt\n\
    else\n\
    echo "L3monCTF{f0rm4t_str1ng_p13_byp4ss}" > /app/flag.txt\n\
    fi\n\
    chmod 444 /app/flag.txt\n\
    exec socat TCP-LISTEN:1337,reuseaddr,fork EXEC:./format_pie' > /entrypoint.sh && chmod +x /entrypoint.sh

# Default FLAG
ENV FLAG="L3monCTF{f0rm4t_str1ng_p13_byp4ss}"

EXPOSE 1337

CMD ["/entrypoint.sh"]
