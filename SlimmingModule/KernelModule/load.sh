#!/bin/bash

sudo insmod speaker.ko

module="speaker_driver"

major=$(awk "\$2==\"$module\" {print \$1}" /proc/devices)
sudo mknod /dev/speaker c $major 0

sudo chmod 777 /dev/speaker
