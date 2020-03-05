## speaker

# Profiling
Need new feature of runc (SCMP_ACT_LOG)

See uninstall-docker.sh to see how to uninstall the current version docker
See install-docker.sh to see how to install the lastest version docker


Using the following cmd to get audit log
``tail -f /var/log/audit/audit.log | grep SECCOMP``
``ausearch -m 1326``

