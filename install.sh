#!/bin/bash
# Assumes sudo, apt-get, pipx and nvm are available
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update
# Pull in debian packages
curl -L https://quarto.org/download/latest/quarto-linux-amd64.deb -o /tmp/quarto.deb
sudo apt-get -y --no-install-recommends install weasyprint wkhtmltopdf /tmp/quarto.deb
sudo apt-get clean; rm /tmp/quarto.deb
# Install python project
python3 -m pip install .
# Add azure cli extensions
az extension add -n log-analytics -y
# Install node component
nvm install
npm install
