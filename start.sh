#!/bin/sh

# Start cron in the background
crond -f -l 2 &

# Start Node server
node server.js
