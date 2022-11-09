#!/bin/bash
poetry install
npm install
git submodule update --init
