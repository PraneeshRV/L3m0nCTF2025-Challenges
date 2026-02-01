#!/bin/bash
# Write FLAG from environment variable to flag file
if [ -n "$FLAG" ]; then
    echo "$FLAG" > /root/flag.txt
else
    echo "L3m0nCTF{4g3n7_45_m15510n_c0mpl373d}" > /root/flag.txt
fi
chmod 644 /root/flag.txt

# Start the application
exec python app.py
