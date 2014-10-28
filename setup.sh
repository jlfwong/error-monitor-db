#!/bin/bash

# Assumes that this repo is checked out at /home/ubuntu/error-monitor-db

apt-get update
apt-get -y install redis-server python-pip python-dev python-numpy python-scipy
pip install Flask
pip install oauth2client
pip install google-api-python-client
pip install redis

cp /home/ubuntu/error-monitor-db/server.conf /etc/init/error-monitor-db.conf
chown root:root /etc/init/error-monitor-db.conf
chmod 644 /etc/init/error-monitor-db.conf

start error-monitor-db

# Now you need to log in and run "cd /home/ubuntu/error-monitor-db && python
# error_parser.py" manually in order to get the BigQuery auth token.

# In order to get Maniphest tasks working, you need to put a valid .arcrc
# in /root/
