# SPEAKER: Split-Phase Execution of Application Containers

## Prerequisites
* **OS**: Ubuntu 16.04 with kernel version 4.15.0
* **Docker**: 19.03.6 or higher (can be installed by using [this script](./install-docker.sh))
* **Linux seccomp filter**: run the command ``apt-get -y install libseccomp-dev``
* **Linux audit**: run the command ``apt-get -y install auditd``


## Using the SPEAKER
The SPEAKER includes two modules: **Tracing Module** and **Slimming Module**. The Tracing Module is implemented as a Python script, which would trace all the system calls invoked in booting, running and shutdown phases of a container application and generate the corresponding system call lists. The Slimming Module takes the outputs of Tracing Module as inputs to build and automatically enforce the corresponding Seccomp Filters during the different execution phases of a container.

### Tracing Module
The Tracing Module utilizes the Linux audit log where the invoked syscall could be recorded if it does not match any of the configured Seccomp Filter rules. We set the Seccomp Filter null so that all the syscalls invoked by the container application will be collected by analyzing the audit log. To make sure all the audit log during tracing will be kept, set ``num_logs`` and ``max_log_file`` to appropriate values in ``/etc/audit/auditd.conf`` (refer [Linux man page](https://linux.die.net/man/5/auditd.conf) for more about the audit configuration).

The Tracing Module could be executed with the following command. In ``speaker/TracingModule``:
```
$ sudo python tracing.py

# An example:
# sudo docker run --security-opt seccomp:./log.json -p 3306:3306 -e MYSQL_ROOT_PASSWORD=mysql -d percona
# c30efc346f75fe0994c57325c1608feabd8b7792e84e9dd8efeff1a053fb2951
# Please wait for container to start up.
# Please perform normal operations on the running docker application.
# After that, to stop the docker, input: docker stop $container_id
# docker stop c30 -t 900
```
Then, follow the output instructions of the script to run a docker container, wait at least 120 seconds for container to warm up, perform normal operations as much as possible (e.g., benchmarking and load testing tool [HammerDB](https://sourceforge.net/projects/hammerdb/files/HammerDB/HammerDB-3.2/HammerDB-3.2-Linux.tar.gz/download)), and gracefully shutdown the container.

After that, three syscall lists will be generated for booting, running, and shutdown phases in the folder ``speaker/profile``. You can also prepare the syscall lists by yourself (refer [syscall list examples](./ProfileExample) for format).

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
3. Perform your normal operations on this container application. Use ``docker stop`` to gracefully shutdown when you would like to stop it. To unload the kernel module, in ``speaker/SlimmingModule/KernelModule``:
```
$ sudo ./unload.sh
```
4. Check the violations of Seccomp Filter rules by the following command. Violated syscall can be added into corresponding profiles if necessery. 
```
$ tail -f /var/log/audit/audit.log | grep SECCOMP
```
