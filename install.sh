#!/bin/bash
# Assumes poetry and npm are available
poetry install 
poetry run az extension add -n log-analytics -y
pushd atlaskit-transformer
npm clean-install --global
popd