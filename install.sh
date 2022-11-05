#!/bin/bash
# Assumes sudo, apt-get, pipx and nvm are available
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update
# Pull in core debian packages
sudo apt-get -y install weasyprint
# Install python project
pipx install poetry
poetry install
# Install node component
nvm install
npm install