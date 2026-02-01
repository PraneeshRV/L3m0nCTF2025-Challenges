#!/bin/bash
# Write the FLAG env var to flag.txt (for SSTI to read)
echo "${FLAG:-L3m0nctf{p4th_tr4v3rs4l_plu5_x55_15_fun}}" > /app/flag.txt
# Start supervisord
exec /usr/bin/supervisord
