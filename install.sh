#!/bin/bash
# Assumes sudo, apt-get and nvm are available
export DEBIAN_FRONTEND=noninteractive
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
echo /opt/az/lib/python3.10/site-packages | sudo tee -a /opt/conda/lib/python3.10/site-packages/azcli.pth
# Pull in debian packages
curl -sL https://quarto.org/download/latest/quarto-linux-amd64.deb -o /tmp/quarto.deb
sudo apt-get -y --no-install-recommends install weasyprint wkhtmltopdf /tmp/quarto.deb
sudo apt-get clean -y && sudo rm -rf /var/lib/apt/lists/* /tmp/quarto.deb
# Install python project
pip install -e .
# Add azure cli extensions
az extension add -n log-analytics -y
# Install node component
nvm install
npm install
