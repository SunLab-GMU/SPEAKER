#!/bin/bash

LINUX_VERSION=`uname -r`
SYSTEM_MAP=/proc/kallsyms

if [ ! -f ${SYSTEM_MAP} ]
then
    echo "Error: file ${SYSTEM_MAP} cannot be found."
    exit -1
fi

function get_addr {
    cat ${SYSTEM_MAP} | grep "\<$1\>" | awk '{print "0x"$1}'
}

function check_addr {
    if [ "x"$2 = "x" ]
    then
        echo "Error: $1 does not exist in ${SYSTEM_MAP}"
        exit -1
    fi
}

BPF_PROG_REALLOC=`get_addr "bpf_prog_realloc"`
check_addr bpf_prog_realloc $BPF_PROG_REALLOC

sudo insmod speaker.ko\
	addr_prog_realloc=$BPF_PROG_REALLOC

module="honeypage_driver"

major=$(awk "\$2==\"$module\" {print \$1}" /proc/devices)
sudo mknod /dev/chrdev c $major 0

sudo chmod 777 /dev/chrdev
