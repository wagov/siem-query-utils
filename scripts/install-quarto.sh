#!/bin/bash
if [[ $(uname -m) == "x86_64" ]]; then # grab prebuilt version
    curl -sL https://quarto.org/download/latest/quarto-linux-amd64.deb -o /tmp/quarto.deb
    apt-get -y install /tmp/quarto.deb && rm /tmp/quarto.deb;
else
    echo "sorry no quarto for arm64 yet"
fi