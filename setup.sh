#!/bin/bash

apt-get update
apt-get -y install redis-server python-pip
pip install Flask
pip install oauth2client
pip install google-api-python-client
pip install redis

cp /home/ubuntu/error-monitor-db/server.conf /etc/init/error-monitor-db.conf
chown root:root /etc/init/error-monitor-db.conf
chmod 644 /etc/init/error-monitor-db.conf

start error-monitor-db
