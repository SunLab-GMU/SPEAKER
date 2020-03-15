import os
import time

callTable = ['read', 'write', 'open', 'close', 'stat', 'fstat', 'lstat', 'poll', 'lseek', 'mmap', 'mprotect', 'munmap', 'brk', 'rt_sigaction', 'rt_sigprocmask', 'rt_sigreturn', 'ioctl', 'pread64', 'pwrite64', 'readv', 'writev', 'access', 'pipe', 'select', 'sched_yield', 'mremap', 'msync', 'mincore', 'madvise', 'shmget', 'shmat', 'shmctl', 'dup', 'dup2', 'pause', 'nanosleep', 'getitimer', 'alarm', 'setitimer', 'getpid', 'sendfile', 'socket', 'connect', 'accept', 'sendto', 'recvfrom', 'sendmsg', 'recvmsg', 'shutdown', 'bind', 'listen', 'getsockname', 'getpeername', 'socketpair', 'setsockopt', 'getsockopt', 'clone', 'fork', 'vfork', 'execve', 'exit', 'wait4', 'kill', 'uname', 'semget', 'semop', 'semctl', 'shmdt', 'msgget', 'msgsnd', 'msgrcv', 'msgctl', 'fcntl', 'flock', 'fsync', 'fdatasync', 'truncate', 'ftruncate', 'getdents', 'getcwd', 'chdir', 'fchdir', 'rename', 'mkdir', 'rmdir', 'creat', 'link', 'unlink', 'symlink', 'readlink', 'chmod', 'fchmod', 'chown', 'fchown', 'lchown', 'umask', 'gettimeofday', 'getrlimit', 'getrusage', 'sysinfo', 'times', 'ptrace', 'getuid', 'syslog', 'getgid', 'setuid', 'setgid', 'geteuid', 'getegid', 'setpgid', 'getppid', 'getpgrp', 'setsid', 'setreuid', 'setregid', 'getgroups', 'setgroups', 'setresuid', 'getresuid', 'setresgid', 'getresgid', 'getpgid', 'setfsuid', 'setfsgid', 'getsid', 'capget', 'capset', 'rt_sigpending', 'rt_sigtimedwait', 'rt_sigqueueinfo', 'rt_sigsuspend', 'sigaltstack', 'utime', 'mknod', 'uselib', 'personality', 'ustat', 'statfs', 'fstatfs', 'sysfs', 'getpriority', 'setpriority', 'sched_setparam', 'sched_getparam', 'sched_setscheduler', 'sched_getscheduler', 'sched_get_priority_max', 'sched_get_priority_min', 'sched_rr_get_interval', 'mlock', 'munlock', 'mlockall', 'munlockall', 'vhangup', 'modify_ldt', 'pivot_root', '_sysctl', 'prctl', 'arch_prctl', 'adjtimex', 'setrlimit', 'chroot', 'sync', 'acct', 'settimeofday', 'mount', 'umount2', 'swapon', 'swapoff', 'reboot', 'sethostname', 'setdomainname', 'iopl', 'ioperm', 'create_module', 'init_module', 'delete_module', 'get_kernel_syms', 'query_module', 'quotactl', 'nfsservctl', 'getpmsg', 'putpmsg', 'afs_syscall', 'tuxcall', 'security', 'gettid', 'readahead', 'setxattr', 'lsetxattr', 'fsetxattr', 'getxattr', 'lgetxattr', 'fgetxattr', 'listxattr', 'llistxattr', 'flistxattr', 'removexattr', 'lremovexattr', 'fremovexattr', 'tkill', 'time', 'futex', 'sched_setaffinity', 'sched_getaffinity', 'set_thread_area', 'io_setup', 'io_destroy', 'io_getevents', 'io_submit', 'io_cancel', 'get_thread_area', 'lookup_dcookie', 'epoll_create', 'epoll_ctl_old', 'epoll_wait_old', 'remap_file_pages', 'getdents64', 'set_tid_address', 'restart_syscall', 'semtimedop', 'fadvise64', 'timer_create', 'timer_settime', 'timer_gettime', 'timer_getoverrun', 'timer_delete', 'clock_settime', 'clock_gettime', 'clock_getres', 'clock_nanosleep', 'exit_group', 'epoll_wait', 'epoll_ctl', 'tgkill', 'utimes', 'vserver', 'mbind', 'set_mempolicy', 'get_mempolicy', 'mq_open', 'mq_unlink', 'mq_timedsend', 'mq_timedreceive', 'mq_notify', 'mq_getsetattr', 'kexec_load', 'waitid', 'add_key', 'request_key', 'keyctl', 'ioprio_set', 'ioprio_get', 'inotify_init', 'inotify_add_watch', 'inotify_rm_watch', 'migrate_pages', 'openat', 'mkdirat', 'mknodat', 'fchownat', 'futimesat', 'newfstatat', 'unlinkat', 'renameat', 'linkat', 'symlinkat', 'readlinkat', 'fchmodat', 'faccessat', 'pselect6', 'ppoll', 'unshare', 'set_robust_list', 'get_robust_list', 'splice', 'tee', 'sync_file_range', 'vmsplice', 'move_pages', 'utimensat', 'epoll_pwait', 'signalfd', 'timerfd_create', 'eventfd', 'fallocate', 'timerfd_settime', 'timerfd_gettime', 'accept4', 'signalfd4', 'eventfd2', 'epoll_create1', 'dup3', 'pipe2', 'inotify_init1', 'preadv', 'pwritev', 'rt_tgsigqueueinfo', 'perf_event_open', 'recvmmsg', 'fanotify_init', 'fanotify_mark', 'prlimit64', 'name_to_handle_at', 'open_by_handle_at', 'clock_adjtime', 'syncfs', 'sendmmsg', 'setns', 'getcpu', 'process_vm_readv', 'process_vm_writev', 'kcmp', 'finit_module', 'sched_setattr', 'sched_getattr', 'renameat2', 'seccomp', 'getrandom', 'memfd_create', 'kexec_file_load', 'bpf', 'execveat', 'userfaultfd', 'membarrier', 'mlock2']

def build_whitelist(booting_t, shutdown_t):
	path = "./audit"
	files= os.listdir(path)
	log_num = len(files)

	booting_list = []
	running_list = []
	shutdown_list = []

	time = []
	call_per_second = []

	cur_t = int(booting_t)
	cur_call_set = []

	#print booting_t, shutdown_t

	for i in range(log_num-1,-1,-1):
		if i != 0:
			f = open('./audit/audit.log.'+str(i))
		else:
			f = open('./audit/audit.log')
		lines = f.readlines()
		f.close()

		for line in lines:
			if "type=SECCOMP" in line:
				audit_t = float(line[line.find('msg=audit(')+10:line.find(':')])
				if audit_t < booting_t:
					continue

				if audit_t >= shutdown_t:
					cur_call = line[line.find("syscall="):].split()[0][8:]
					if cur_call not in shutdown_list:
						shutdown_list.append(cur_call)
					continue

				if int(audit_t) > cur_t:
					time.append(cur_t)
					call_per_second.append(cur_call_set)
					cur_t = audit_t
					cur_call_set = []

				cur_call = line[line.find("syscall="):].split()[0][8:]
				if cur_call not in cur_call_set:
					cur_call_set.append(cur_call)

	time.append(cur_t)
	call_per_second.append(cur_call_set)


	running_pt_index = -1
	for i in range(1, len(call_per_second)-2):
		if (set(call_per_second[i-1]) == set(call_per_second[i]) and 
			set(call_per_second[i]) == set(call_per_second[i+1]) and
			set(call_per_second[i]) == set(call_per_second[i+2]) and
			len(list(set(call_per_second[i]))) < 8):
			running_pt_index = i
			#print call_per_second[i]
			break

	#print time[running_pt_index]

	for i in range(0, running_pt_index):
		booting_list = set(list(booting_list)+call_per_second[i])

	for i in range(running_pt_index, len(call_per_second)):
		running_list = set(list(running_list)+call_per_second[i])

	#print len(booting_list), len(running_list), len(shutdown_list)

	f = open("./booting", 'w+')
	for item in booting_list:
		f.write(callTable[int(item)]+'\n')
	f.close()

	f = open("./running", 'w+')
	for item in running_list:
		f.write(callTable[int(item)]+'\n')
	f.close()

	f = open("./shutdown", 'w+')
	for item in shutdown_list:
		f.write(callTable[int(item)]+'\n')
	f.close()

	booting_and_running = list(set(booting_list)&set(running_list))
	running_and_shutdown = list(set(running_list)&set(shutdown_list))
	only_boooting = list(set(booting_list)-set(booting_and_running))
	only_running = list(set(running_list)-set(booting_and_running)-set(running_and_shutdown))
	only_shutdown = list(set(shutdown_list)-set(running_and_shutdown))

	# print len(only_boooting), only_boooting
	# print len(booting_and_running), booting_and_running
	# print len(only_running), only_running
	# print len(running_and_shutdown), running_and_shutdown
	# print len(only_shutdown), only_shutdown


def main():
	#Empty system log and restart log service
	#Note: make sure there is enough space for log
	#E.g., make num_logs = 99 in /etc/audit/auditd.conf
	#os.system('rm /var/log/audit/audit*')
	os.system('service auditd restart')

	#docker_run_cmd = 'sudo docker run --security-opt seccomp:./log.json -p 5432:5432 -e POSTGRES_PASSWORD=postgres -d postgres'
	#docker_run_cmd = 'docker run --security-opt seccomp:./log.json -d -p 27017:27017 -e MONGO_INITDB_ROOT_USERNAME=mongoadmin -e MONGO_INITDB_ROOT_PASSWORD=secret mongo'
	#./bin/ycsb run mongodb -s -P workloads/workloada -p recordcount=10000 -threads 16 -p mongodb.url="mongodb://mongoadmin:secret@127.0.0.1:27017" -p mongodb.auth="true"
	#docker_run_cmd = 'sudo docker run --security-opt seccomp:./log.json -p 3306:3306 -e MYSQL_ROOT_PASSWORD=mysql -d percona'
	docker_run_cmd = raw_input('To run the docker, input: docker run --security-opt seccomp:./log.json [OPT] IMG[:TAG|@DIGEST] [CMD] [ARG...]\n')
	booting_t = time.time()
	os.system(docker_run_cmd)

	print('Please wait 120s for container to start up.')
	time.sleep(120)

	print('Please perform normal operations on the running docker application.')

	docker_stop_cmd = raw_input('After that, to stop the docker, input: docker stop $container_id\n')
	shutdown_t = time.time()
	os.system(docker_stop_cmd)

	#Transfer log
	if not os.path.exists('./audit'):
		os.system('mkdir audit')
	os.system('cp /var/log/audit/audit* ./audit/')
	os.system('chmod 777 ./audit')
	os.system('chmod 777 ./audit/*')

	build_whitelist(booting_t, shutdown_t)


if __name__ == '__main__':
    main()
