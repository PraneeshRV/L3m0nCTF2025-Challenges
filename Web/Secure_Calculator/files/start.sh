#!/bin/bash

# Check if FLAG environment variable is set
if [ -z "$FLAG" ]; then
    echo "L3monCTF{sh3ll_inj3ct10n_is_n0t_m4th}" > flag.txt
else
    echo "$FLAG" > flag.txt
fi

# Ensure flag is readable
chmod 644 flag.txt

# Start the application
python app.py
