#!/bin/bash

apt-get update
apt-get -y install redis-server python-pip
pip install Flask
pip install oauth2client
pip install google-api-python-client
pip install redis
