# SPEAKER: Split-Phase Execution of Application Containers

SPEAKER is a system call reduction mechanism to reduce the attack surface of Linux application containers. It works by first tracing the available system calls necessary for the booting, running, and shutdown phases of the application containers, and then dynamically changing the seccomp filter to update the available system calls for each phase. SPEAKER runs outside the containers and is completely non-intrusive to the application containers. Our evaluation results show that SPEAKER can significantly reduce the system call interface and incurs almost no performance overhead.

## Prerequisites
* **OS**: Ubuntu 16.04 with kernel version 4.15.0 (can be downloaded [here](https://releases.ubuntu.com/16.04/ubuntu-16.04.6-desktop-amd64.iso))
* **Docker**: 19.03.6 or higher (can be installed by using [this script](./install-docker.sh))
* **Linux seccomp filter**: run the command ``apt-get -y install libseccomp-dev``
* **Linux audit**: run the command ``apt-get -y install auditd``
* **Container image**: most can be pulled from [Docker Hub](https://hub.docker.com)

A VMware image with all above can be found [here](https://nam11.safelinks.protection.outlook.com/?url=https%3A%2F%2Fdrive.google.com%2Ffile%2Fd%2F1m0xoH_U_9tXzaRwyKEIVtO8A-GARgxun%2Fview%3Fusp%3Dshare_link&data=05%7C01%7Cxwang44%40gmu.edu%7C9a1d11b871b14681dbaf08dada261618%7C9e857255df574c47a0c00546460380cb%7C0%7C0%7C638062154356574428%7CUnknown%7CTWFpbGZsb3d8eyJWIjoiMC4wLjAwMDAiLCJQIjoiV2luMzIiLCJBTiI6Ik1haWwiLCJXVCI6Mn0%3D%7C3000%7C%7C%7C&sdata=799ZsZzLlol7bsD%2BRGaYiWwpZpPS%2BPySu2noGhBga0w%3D&reserved=0) (password 123).


## Using the SPEAKER
The SPEAKER includes two modules: **Tracing Module** and **Slimming Module**. The Tracing Module is implemented as a Python script, which would trace all the system calls invoked in booting, running, and shutdown phases of a container application and generate the corresponding system call lists. The Slimming Module takes the outputs of Tracing Module as inputs to build and automatically enforce the corresponding Seccomp Filters during the different execution phases of a container.

### Tracing Module
The Tracing Module utilizes the Linux audit log where the invoked syscall could be recorded if it does not match any of the configured Seccomp Filter rules. We set the Seccomp Filter null so that all the syscalls invoked by the container application will be collected by analyzing the audit log. To make sure all the audit log during tracing will be kept, set ``num_logs`` and ``max_log_file`` to appropriate values in ``/etc/audit/auditd.conf`` (refer [Linux man page](https://linux.die.net/man/5/auditd.conf) for more about the audit configuration).

The Tracing Module could be executed with the following command. In ``speaker/TracingModule``:
```
$ sudo python tracing.py

```
Then, follow the output instructions of the script to run a docker container, wait enough time (e.g., 120s) for container to warm up, perform normal operations as much as possible (e.g., benchmarking and load testing tool [HammerDB](https://sourceforge.net/projects/hammerdb/files/HammerDB/HammerDB-3.2/HammerDB-3.2-Linux.tar.gz/download), ``apt install libmysqlclient-dev`` is required), and gracefully shutdown the container.

After that, three syscall lists will be generated for booting, running, and shutdown phases in the folder ``speaker/profile``. You can also prepare the syscall lists by yourself (refer [syscall list examples](./ProfileExample) for format). Note: make sure three syscall lists are in ``speaker/profile``.

### Slimming Module
1. Build and load the kernel module that could dynamically modify the Seccomp Filter. In ``speaker/SlimmingModule/KernelModule``:
```
$ sudo make
$ sudo ./load.sh
```
2. Run the user program to start up the container, automatically identify the execution phase, and notify the kernel module to update the Seccomp Filter. In ``speaker/SlimmingModule/UserProgram``:
```
$ sudo make
$ sudo ./speakeru -service SERVICE_NAME -cmd DOCKER_RUN_COMMAND

# SERVICE_NAME is the name of first process within the container, DOCKER_RUN_COMMAND is the normal command to run the container
# An example: sudo ./speakeru -service mysqld -cmd "docker run -p 3306:3306 -e MYSQL_ROOT_PASSWORD=mysql -d percona"
# Note: use quotes for DOCKER_RUN_COMMAND
```
3. Perform your normal operations on this container application. After that, use ``docker stop`` to gracefully shut down when you would like to stop it. To unload the kernel module, in ``speaker/SlimmingModule/KernelModule``:
```
# After finishing all the operation on the container and successfully shutting down it:
$ sudo ./unload.sh
```
4. Check the violations of Seccomp Filter rules by the following command. Violated syscall can be manually added into corresponding profiles if necessary. 
```
$ tail -f /var/log/audit/audit.log | grep SECCOMP
```
