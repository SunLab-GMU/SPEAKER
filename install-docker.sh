#!/bin/bash

# this shell script can install docker which supports the option SCMP_ACT_LOG of seccomp 
sudo apt-get remove docker docker-engine docker.io containerd runc
sudo apt-get update

sudo apt-get install \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg-agent \
    software-properties-common

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

sudo add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable nightly test"
   
sudo apt-get update

sudo apt-get install docker-ce docker-ce-cli containerd.io

sudo apt-get install docker-ce=5:19.03.6~3-0~ubuntu-xenial docker-ce-cli=5:19.03.6~3-0~ubuntu-xenial containerd.io
