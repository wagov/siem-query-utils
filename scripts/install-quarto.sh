#!/bin/bash
if [[ $(uname -m) == "x86_64" ]]; then # grab prebuilt version
    curl -sL https://github.com/quarto-dev/quarto-cli/releases/download/v1.3.142/quarto-1.3.142-linux-amd64.deb -o /tmp/quarto.deb
    apt-get -y install /tmp/quarto.deb && rm /tmp/quarto.deb
    quarto install tool tinytex
else
    echo "sorry no quarto for arm64 yet"
fi