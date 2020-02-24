#include <stdio.h>
#include <stdlib.h>
#include <seccomp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <wait.h>
#include <sys/time.h>
#include <sys/user.h>
#include "syscall_table.h"

typedef struct request{
	int pid;
	int lenf;
	uint8_t* bpf_code;
} REQUEST;



//Two input argvs: System call list file path; Pid of the first container process
void prepare_filter(int pid_num, char *filepath_name, int op)
{
	//parse the arguments
	int pid=pid_num;
	char* filepath=filepath_name;
	char* tmppath="/tmp/seccomp_filter.bpf";
	//printf("pid=%d,filepath=%s\r\n\r\n",pid,filepath);
	struct stat st;
	int rc = -1;
	scmp_filter_ctx ctx;
	int filter_fd;

	FILE *stream;
        char *line = NULL;
        size_t lenline = 0;
        ssize_t rs;
	int sumline=0;

	

	int chrdev_fd = open("/dev/chrdev", O_RDWR);
	if(chrdev_fd == -1){
		printf("Failed to open device!\n");
		return 0;
	}

	//parse the input syscall file

	ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL)
		goto out;

	if (seccomp_arch_exist(ctx, SCMP_ARCH_X86_64) == -EEXIST) {
		rc = seccomp_arch_add(ctx, SCMP_ARCH_X86_64);
		if (rc != 0)
			goto out;
	}
	if (seccomp_arch_exist(ctx, SCMP_ARCH_X86) == -EEXIST) {
		rc = seccomp_arch_add(ctx, SCMP_ARCH_X86);
		if (rc != 0)
			goto out;
	}
	if (seccomp_arch_exist(ctx, SCMP_ARCH_X32) == -EEXIST) {
		rc = seccomp_arch_add(ctx, SCMP_ARCH_X32);
		if (rc != 0)
			goto out;
	}
	//rc = seccomp_arch_remove(ctx, SCMP_ARCH_NATIVE);
	//if (rc != 0)
	//	goto out;

        stream = fopen(filepath, "r");
        if (stream == NULL)
	{
		printf("open file failed\r\n");
		goto out; 
	}

        while ((rs = getline(&line, &lenline, stream)) != -1) 
	{
	     if(line!=NULL && !(line[0] == ' ') && !(line[0] == '\n' || line[0] == '\r')) 
	     {	
             	//printf("%d,%s", sumline,line);
		if(line[strlen(line)-1]=='\r' || line[strlen(line)-1]=='\n')
		line[strlen(line)-1]='\0';
		//printf("%d,%s\r\n",sumline,line);
		sumline++;
		if(strcmp(line, "read")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "write")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "open")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "close")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "stat")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "fstat")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "lstat")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lstat),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "poll")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(poll),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "lseek")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "mmap")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "mprotect")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "munmap")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "brk")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "rt_sigaction")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "rt_sigprocmask")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "rt_sigreturn")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "ioctl")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "pread64")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pread64),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "pwrite64")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pwrite64),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "readv")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readv),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "writev")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "access")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "pipe")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pipe),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "select")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(select),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "sched_yield")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_yield),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "mremap")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mremap),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "msync")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(msync),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "mincore")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mincore),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "madvise")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(madvise),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "shmget")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shmget),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "shmat")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shmat),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "shmctl")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shmctl),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "dup")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "dup2")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "pause")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pause),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "nanosleep")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "getitimer")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getitimer),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "alarm")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(alarm),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "setitimer")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setitimer),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "getpid")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "sendfile")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "socket")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "connect")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "accept")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "sendto")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "recvfrom")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "sendmsg")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmsg),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "recvmsg")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmsg),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "shutdown")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shutdown),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "bind")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(bind),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "listen")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(listen),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "getsockname")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockname),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "getpeername")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpeername),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "socketpair")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socketpair),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "setsockopt")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsockopt),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "getsockopt")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockopt),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "clone")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "fork")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fork),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "vfork")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(vfork),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "execve")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "exit")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "wait4")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "kill")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(kill),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "uname")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(uname),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "semget")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(semget),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "semop")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(semop),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "semctl")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(semctl),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "shmdt")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shmdt),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "msgget")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(msgget),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "msgsnd")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(msgsnd),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "msgrcv")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(msgrcv),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "msgctl")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(msgctl),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "fcntl")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "flock")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(flock),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "fsync")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fsync),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "fdatasync")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fdatasync),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "truncate")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(truncate),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "ftruncate")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ftruncate),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "getdents")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "getcwd")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getcwd),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "chdir")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chdir),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "fchdir")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchdir),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "rename")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rename),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "mkdir")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdir),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "rmdir")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rmdir),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "creat")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(creat),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "link")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(link),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "unlink")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unlink),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "symlink")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(symlink),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "readlink")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlink),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "chmod")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chmod),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "fchmod")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchmod),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "chown")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chown),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "fchown")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchown),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "lchown")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lchown),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "umask")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(umask),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "gettimeofday")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettimeofday),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "getrlimit")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrlimit),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "getrusage")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrusage),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "sysinfo")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sysinfo),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "times")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(times),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "ptrace")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ptrace),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "getuid")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "syslog")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(syslog),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "getgid")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "setuid")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setuid),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "setgid")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setgid),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "geteuid")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "getegid")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getegid),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "setpgid")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setpgid),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "getppid")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getppid),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "getpgrp")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpgrp),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "setsid")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsid),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "setreuid")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setreuid),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "setregid")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setregid),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "getgroups")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgroups),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "setgroups")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setgroups),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "setresuid")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setresuid),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "getresuid")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getresuid),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "setresgid")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setresgid),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "getresgid")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getresgid),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "getpgid")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpgid),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "setfsuid")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setfsuid),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "setfsgid")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setfsgid),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "getsid")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsid),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "capget")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(capget),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "capset")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(capset),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "rt_sigpending")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigpending),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "rt_sigtimedwait")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigtimedwait),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "rt_sigqueueinfo")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigqueueinfo),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "rt_sigsuspend")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigsuspend),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "sigaltstack")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sigaltstack),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "utime")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(utime),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "mknod")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mknod),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "uselib")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(uselib),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "personality")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(personality),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "ustat")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ustat),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "statfs")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(statfs),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "fstatfs")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstatfs),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "sysfs")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sysfs),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "getpriority")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpriority),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "setpriority")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setpriority),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "sched_setparam")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_setparam),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "sched_getparam")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_getparam),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "sched_setscheduler")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_setscheduler),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "sched_getscheduler")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_getscheduler),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "sched_get_priority_max")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_get_priority_max),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "sched_get_priority_min")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_get_priority_min),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "sched_rr_get_interval")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_rr_get_interval),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "mlock")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mlock),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "munlock")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munlock),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "mlockall")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mlockall),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "munlockall")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munlockall),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "vhangup")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(vhangup),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "modify_ldt")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(modify_ldt),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "pivot_root")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pivot_root),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "_sysctl")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(_sysctl),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "prctl")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "arch_prctl")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "adjtimex")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(adjtimex),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "setrlimit")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setrlimit),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "chroot")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chroot),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "sync")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sync),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "acct")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(acct),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "settimeofday")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(settimeofday),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "mount")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mount),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "umount2")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(umount2),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "swapon")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(swapon),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "swapoff")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(swapoff),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "reboot")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(reboot),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "sethostname")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sethostname),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "setdomainname")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setdomainname),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "iopl")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(iopl),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "ioperm")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioperm),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "create_module")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(create_module),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "init_module")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(init_module),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "delete_module")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(delete_module),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "get_kernel_syms")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(get_kernel_syms),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "query_module")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(query_module),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "quotactl")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(quotactl),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "nfsservctl")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nfsservctl),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "getpmsg")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpmsg),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "putpmsg")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(putpmsg),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "afs_syscall")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(afs_syscall),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "tuxcall")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tuxcall),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "security")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(security),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "gettid")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettid),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "readahead")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readahead),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "setxattr")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setxattr),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "lsetxattr")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lsetxattr),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "fsetxattr")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fsetxattr),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "getxattr")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getxattr),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "lgetxattr")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lgetxattr),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "fgetxattr")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fgetxattr),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "listxattr")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(listxattr),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "llistxattr")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(llistxattr),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "flistxattr")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(flistxattr),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "removexattr")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(removexattr),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "lremovexattr")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lremovexattr),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "fremovexattr")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fremovexattr),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "tkill")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tkill),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "time")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(time),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "futex")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "sched_setaffinity")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_setaffinity),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "sched_getaffinity")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_getaffinity),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "set_thread_area")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_thread_area),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "io_setup")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_setup),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "io_destroy")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_destroy),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "io_getevents")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_getevents),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "io_submit")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_submit),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "io_cancel")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_cancel),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "get_thread_area")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(get_thread_area),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "lookup_dcookie")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lookup_dcookie),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "epoll_create")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_create),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "epoll_ctl_old")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_ctl_old),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "epoll_wait_old")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_wait_old),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "remap_file_pages")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(remap_file_pages),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "getdents64")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents64),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "set_tid_address")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_tid_address),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "restart_syscall")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(restart_syscall),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "semtimedop")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(semtimedop),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "fadvise64")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fadvise64),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "timer_create")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timer_create),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "timer_settime")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timer_settime),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "timer_gettime")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timer_gettime),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "timer_getoverrun")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timer_getoverrun),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "timer_delete")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timer_delete),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "clock_settime")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_settime),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "clock_gettime")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "clock_getres")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_getres),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "clock_nanosleep")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_nanosleep),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "exit_group")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "epoll_wait")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_wait),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "epoll_ctl")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_ctl),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "tgkill")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tgkill),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "utimes")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(utimes),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "vserver")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(vserver),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "mbind")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mbind),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "set_mempolicy")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_mempolicy),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "get_mempolicy")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(get_mempolicy),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "mq_open")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mq_open),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "mq_unlink")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mq_unlink),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "mq_timedsend")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mq_timedsend),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "mq_timedreceive")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mq_timedreceive),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "mq_notify")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mq_notify),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "mq_getsetattr")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mq_getsetattr),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "kexec_load")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(kexec_load),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "waitid")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(waitid),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "add_key")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(add_key),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "request_key")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(request_key),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "keyctl")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(keyctl),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "ioprio_set")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioprio_set),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "ioprio_get")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioprio_get),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "inotify_init")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(inotify_init),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "inotify_add_watch")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(inotify_add_watch),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "inotify_rm_watch")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(inotify_rm_watch),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "migrate_pages")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(migrate_pages),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "openat")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "mkdirat")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdirat),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "mknodat")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mknodat),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "fchownat")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchownat),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "futimesat")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futimesat),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "newfstatat")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "unlinkat")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unlinkat),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "renameat")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(renameat),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "linkat")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(linkat),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "symlinkat")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(symlinkat),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "readlinkat")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlinkat),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "fchmodat")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchmodat),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "faccessat")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(faccessat),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "pselect6")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pselect6),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "ppoll")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ppoll),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "unshare")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unshare),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "set_robust_list")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "get_robust_list")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(get_robust_list),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "splice")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(splice),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "tee")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tee),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "sync_file_range")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sync_file_range),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "vmsplice")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(vmsplice),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "move_pages")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(move_pages),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "utimensat")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(utimensat),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "epoll_pwait")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_pwait),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "signalfd")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(signalfd),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "timerfd_create")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_create),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "eventfd")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(eventfd),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "fallocate")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fallocate),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "timerfd_settime")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_settime),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "timerfd_gettime")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_gettime),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "accept4")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept4),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "signalfd4")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(signalfd4),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "eventfd2")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(eventfd2),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "epoll_create1")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_create1),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "dup3")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup3),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "pipe2")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pipe2),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "inotify_init1")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(inotify_init1),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "preadv")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(preadv),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "pwritev")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pwritev),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "rt_tgsigqueueinfo")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_tgsigqueueinfo),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "perf_event_open")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(perf_event_open),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "recvmmsg")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmmsg),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "fanotify_init")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fanotify_init),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "fanotify_mark")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fanotify_mark),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "prlimit64")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prlimit64),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "name_to_handle_at")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(name_to_handle_at),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "open_by_handle_at")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open_by_handle_at),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "clock_adjtime")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_adjtime),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "syncfs")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(syncfs),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "sendmmsg")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmmsg),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "setns")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setns),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "getcpu")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getcpu),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "process_vm_readv")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(process_vm_readv),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "process_vm_writev")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(process_vm_writev),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "kcmp")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(kcmp),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "finit_module")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(finit_module),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "sched_setattr")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_setattr),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "sched_getattr")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_getattr),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "renameat2")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(renameat2),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "seccomp")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(seccomp),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "getrandom")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "memfd_create")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(memfd_create),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "kexec_file_load")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(kexec_file_load),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "bpf")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(bpf),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "execveat")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execveat),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "userfaultfd")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(userfaultfd),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "membarrier")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(membarrier),0);
			if (rc < 0)
				goto out;
		}
		else if(strcmp(line, "mlock2")==0)
		{
			rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mlock2),0);
			if (rc < 0)
				goto out;
		}
		else
		{
			//printf("unknown system call:%s\r\n",line);
			goto out;
		}
		}
		
	}

	if (0 == access(tmppath,F_OK)) { 
		remove(tmppath);
    		//if(!remove(tmppath))
		//{
		//	printf("remove error aaa,rc=%d\r\n",rc);
		//	rc=-errno;
		//	goto out;
		//} 
	} 

	filter_fd = open(tmppath, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
//open(tmppath,O_RDWR);
	if (filter_fd == -1) {
		printf("open error aaa,rc=%d\r\n",rc);
		rc = -errno;
		goto out;
	}
	rc = seccomp_export_bpf(ctx, filter_fd);
	if (rc < 0) {
		close(filter_fd);
		goto out;
	}

	if (filter_fd == -1) {
		goto out;
	}

	//rc = seccomp_load(ctx);	

	goto out1;

out:
	seccomp_release(ctx);
	return -rc;

out1:

	if(fstat(filter_fd, &st)!=0) {rc=-1;close(filter_fd);}



	int sizeof_sock=sizeof(struct sock_filter);
	struct sock_filter fil[st.st_size/sizeof_sock];
	char aa[sizeof_sock];
	int suma=0;
	int r=0;
	int i = 0;
	while((r = pread(filter_fd, aa, sizeof_sock, suma)) == sizeof_sock) {	
		memcpy((char*)(&(fil[suma/sizeof_sock])), aa, sizeof_sock);	
		suma=suma+r;
	}

	close(filter_fd);

	struct sock_fprog prog = {
		.len = st.st_size/sizeof_sock,
		.filter = fil,
	};
	
	uint8_t *bpf_code = (uint8_t*)malloc(prog.len * sizeof(struct sock_filter));
	memset(bpf_code, '\0', prog.len * sizeof(struct sock_filter));

	for(int i = 0; i < prog.len; i++)
		memcpy(bpf_code + i*sizeof(struct sock_filter), prog.filter + i, sizeof(struct sock_filter));

	REQUEST request;
	request.pid = pid;
	request.lenf = prog.len;
	request.bpf_code = bpf_code;
	ioctl(chrdev_fd, op, &request);
	free(bpf_code);

	return;
	
	// char param[15000];
	// //strncpy(param,"len=",sizeof("len="));
	// memset(param, '\0', 15000);
	// int lenpara=strlen(param);
	// sprintf(param+lenpara,",%u,",(&prog)->len);
	// printf("zzy_len = %d, param = %d\n", lenpara, (&prog)->len);
	// lenpara=strlen(param);

	// printf("pid-para=%d,sock_fprog_addr=%p,sock_fprog.sizeof=%d,current pid in user space=%d,sock_filter.sizeof=%d\r\n",pid,&prog,sizeof(prog),getpid(),sizeof(struct sock_filter));
	// int i=0;
	// int len=(&prog)->len;
	// for(; i<(&prog)->len; i++)
	// {
	// 	//printf("prog[%d],addr=%p,content:code=%#x,jt=%u,jf=%u,k=%#x\r\n",i,&((&prog)->filter[i]),(&((&prog)->filter[i]))->code,(&((&prog)->filter[i]))->jt,(&((&prog)->filter[i]))->jf,(&((&prog)->filter[i]))->k);
	// 	sprintf(param+lenpara,"%u,",(&((&prog)->filter[i]))->code);
	// 	lenpara=strlen(param);
	// 	sprintf(param+lenpara,"%u,",(&((&prog)->filter[i]))->jt);
	// 	lenpara=strlen(param);
	// 	sprintf(param+lenpara,"%u,",(&((&prog)->filter[i]))->jf);
	// 	lenpara=strlen(param);
	// 	if(i<((&prog)->len)-1) sprintf(param+lenpara,"%u,",(&((&prog)->filter[i]))->k);	
	// 	if(i==((&prog)->len)-1) sprintf(param+lenpara,"%u",(&((&prog)->filter[i]))->k);	
	// 	lenpara=strlen(param);
	// 	//printf("%d\n", lenpara);	
	// }
	// printf("zzyzzy:%d\n", lenpara);	
	// char param1[901] = {'\0'};
	// char param2[901] = {'\0'};
	// char param3[901] = {'\0'};
	// char param4[901] = {'\0'};
	// char param5[901] = {'\0'};
	// char param6[901] = {'\0'};
	// char param7[901] = {'\0'};
	// char param8[901] = {'\0'};
	// char param9[901] = {'\0'};




	// if(strlen(param)<=900){
	// 	temp.pid = pid;
	// 	temp.lenf = len;
	// 	temp.num = 1;
	// 	temp.param = (void**)malloc(sizeof(char*)*1);
	// 	temp.param[0] = param;
	// 	//snprintf(cmd, sizeof cmd, "/sbin/insmod /home/lglei/lglei/MTDResearch/implementation/laptop-home/change_seccomplist/change-seccomp.ko pid=%d sock_fprog0=%s lenf=%d",pid,param,len);
	// }
	// else if(strlen(param)>900 && strlen(param)<=900*2) {
	// 	memcpy(param1,param,900);
	// 	memcpy(param2,param+900,strlen(param)-900);

	// 	temp.pid = pid;
	// 	temp.lenf = len;
	// 	temp.num = 2;
	// 	temp.param = (void**)malloc(sizeof(char*)*2);
	// 	temp.param[0] = param1;
	// 	temp.param[1] = param2;
	// //	snprintf(cmd, sizeof cmd, "/sbin/insmod /home/lglei/lglei/MTDResearch/implementation/laptop-home/change_seccomplist/change-seccomp.ko pid=%d sock_fprog0=%s sock_fprog1=%s lenf=%d",pid,param1,param2,len);
	// }
	// else if(strlen(param)>900*2 && strlen(param)<=900*3)
	// {
	// 	memcpy(param1,param,900);
	// 	memcpy(param2,param+900,900);
	// 	memcpy(param3,param+900*2,strlen(param)-900*2);

	// 	temp.pid = pid;
	// 	temp.lenf = len;
	// 	temp.num = 3;
	// 	temp.param = (void**)malloc(sizeof(char*)*3);
	// 	temp.param[0] = param1;
	// 	temp.param[1] = param2;
	// 	temp.param[2] = param3;

	// //	snprintf(cmd, sizeof cmd, "/sbin/insmod /home/lglei/lglei/MTDResearch/implementation/laptop-home/change_seccomplist/change-seccomp.ko pid=%d sock_fprog0=%s sock_fprog1=%s sock_fprog2=%s lenf=%d",pid,param1,param2,param3,len);
	// }
	// else if(strlen(param)>900*3 && strlen(param)<=900*4)
	// {
	// 	memcpy(param1,param,900);
	// 	memcpy(param2,param+900,900);
	// 	memcpy(param3,param+900*2,900);
	// 	memcpy(param4,param+900*3,strlen(param)-900*3);

	// 	temp.pid = pid;
	// 	temp.lenf = len;
	// 	temp.num = 4;
	// 	temp.param = (void**)malloc(sizeof(char*)*4);
	// 	temp.param[0] = param1;
	// 	temp.param[1] = param2;
	// 	temp.param[2] = param3;
	// 	temp.param[3] = param4;
	// //	snprintf(cmd, sizeof cmd, "/sbin/insmod /home/lglei/lglei/MTDResearch/implementation/laptop-home/change_seccomplist/change-seccomp.ko pid=%d sock_fprog0=%s sock_fprog1=%s sock_fprog2=%s sock_fprog3=%s lenf=%d",pid,param1,param2,param3,param4,len);
	// }
	// else if(strlen(param)>900*4 && strlen(param)<=900*5)
	// {
	// 	memcpy(param1,param,900);
	// 	memcpy(param2,param+900,900);
	// 	memcpy(param3,param+900*2,900);
	// 	memcpy(param4,param+900*3,900);
	// 	memcpy(param5,param+900*4,strlen(param)-900*4);

	// 	temp.pid = pid;
	// 	temp.lenf = len;
	// 	temp.num = 5;
	// 	temp.param = (void**)malloc(sizeof(char*)*5);
	// 	temp.param[0] = param1;
	// 	temp.param[1] = param2;
	// 	temp.param[2] = param3;
	// 	temp.param[3] = param4;
	// 	temp.param[4] = param5;
	// //	snprintf(cmd, sizeof cmd, "/sbin/insmod /home/lglei/lglei/MTDResearch/implementation/laptop-home/change_seccomplist/change-seccomp.ko pid=%d sock_fprog0=%s sock_fprog1=%s sock_fprog2=%s sock_fprog3=%s sock_fprog4=%s lenf=%d",pid,param1,param2,param3,param4,param5,len);
	// }
	// else if(strlen(param)>900*5 && strlen(param)<=900*6)
	// {
	// 	memcpy(param1,param,900);
	// 	memcpy(param2,param+900,900);
	// 	memcpy(param3,param+900*2,900);
	// 	memcpy(param4,param+900*3,900);
	// 	memcpy(param5,param+900*4,900);
	// 	memcpy(param6,param+900*5,strlen(param)-900*5);

	// 	temp.pid = pid;
	// 	temp.lenf = len;
	// 	temp.num = 6;
	// 	temp.param = (void**)malloc(sizeof(char*)*6);
	// 	temp.param[0] = param1;
	// 	temp.param[1] = param2;
	// 	temp.param[2] = param3;
	// 	temp.param[3] = param4;
	// 	temp.param[4] = param5;
	// 	temp.param[5] = param6;
	// //	snprintf(cmd, sizeof cmd, "/sbin/insmod /home/lglei/lglei/MTDResearch/implementation/laptop-home/change_seccomplist/change-seccomp.ko pid=%d sock_fprog0=%s sock_fprog1=%s sock_fprog2=%s sock_fprog3=%s sock_fprog4=%s sock_fprog5=%s lenf=%d",pid,param1,param2,param3,param4,param5,param6,len);
	// }
	// else if(strlen(param)>900*6 && strlen(param)<=900*7)
	// {
	// 	memcpy(param1,param,900);
	// 	memcpy(param2,param+900,900);
	// 	memcpy(param3,param+900*2,900);
	// 	memcpy(param4,param+900*3,900);
	// 	memcpy(param5,param+900*4,900);
	// 	memcpy(param6,param+900*5,900);
	// 	memcpy(param7,param+900*6,strlen(param)-900*6);

	// 	temp.pid = pid;
	// 	temp.lenf = len;
	// 	temp.num = 7;
	// 	temp.param = (void**)malloc(sizeof(char*)*7);
	// 	temp.param[0] = param1;
	// 	temp.param[1] = param2;
	// 	temp.param[2] = param3;
	// 	temp.param[3] = param4;
	// 	temp.param[4] = param5;
	// 	temp.param[5] = param6;
	// 	temp.param[6] = param7;
	// //	snprintf(cmd, sizeof cmd, "/sbin/insmod /home/lglei/lglei/MTDResearch/implementation/laptop-home/change_seccomplist/change-seccomp.ko pid=%d sock_fprog0=%s sock_fprog1=%s sock_fprog2=%s sock_fprog3=%s sock_fprog4=%s sock_fprog5=%s sock_fprog6=%s lenf=%d",pid,param1,param2,param3,param4,param5,param6,param7,len);
	// }
	// else if(strlen(param)>900*7 && strlen(param)<=900*8)
	// {
	// 	memcpy(param1,param,900);
	// 	memcpy(param2,param+900,900);
	// 	memcpy(param3,param+900*2,900);
	// 	memcpy(param4,param+900*3,900);
	// 	memcpy(param5,param+900*4,900);
	// 	memcpy(param6,param+900*5,900);
	// 	memcpy(param7,param+900*6,900);
	// 	memcpy(param8,param+900*7,strlen(param)-900*7);

	// 	temp.pid = pid;
	// 	temp.lenf = len;
	// 	temp.num = 8;
	// 	temp.param = (void**)malloc(sizeof(char*)*8);
	// 	temp.param[0] = param1;
	// 	temp.param[1] = param2;
	// 	temp.param[2] = param3;
	// 	temp.param[3] = param4;
	// 	temp.param[4] = param5;
	// 	temp.param[5] = param6;
	// 	temp.param[6] = param7;
	// 	temp.param[7] = param8;
	// //	snprintf(cmd, sizeof cmd, "/sbin/insmod /home/lglei/lglei/MTDResearch/implementation/laptop-home/change_seccomplist/change-seccomp.ko pid=%d sock_fprog0=%s sock_fprog1=%s sock_fprog2=%s sock_fprog3=%s sock_fprog4=%s sock_fprog5=%s sock_fprog6=%s sock_fprog7=%s lenf=%d",pid,param1,param2,param3,param4,param5,param6,param7,param8,len);
	// }
	// else if(strlen(param)>900*8 && strlen(param)<=900*9)
	// {
	// 	memset(param1,'\0',901);
	// 	memset(param2,'\0',901);
	// 	memset(param3,'\0',901);
	// 	memset(param4,'\0',901);
	// 	memset(param5,'\0',901);
	// 	memset(param6,'\0',901);
	// 	memset(param7,'\0',901);
	// 	memset(param8,'\0',901);
	// 	memset(param9,'\0',901);
	// 	memcpy(param1,param,900);
	// 	memcpy(param2,param+900,900);
	// 	memcpy(param3,param+900*2,900);
	// 	memcpy(param4,param+900*3,900);
	// 	memcpy(param5,param+900*4,900);
	// 	memcpy(param6,param+900*5,900);
	// 	memcpy(param7,param+900*6,900);
	// 	memcpy(param8,param+900*7,900);
	// 	memcpy(param9,param+900*8,strlen(param)-900*8);

	// 	temp.pid = pid;
	// 	temp.lenf = len;
	// 	temp.num = 9;
	// 	temp.param = (void**)malloc(sizeof(char*)*9);
	// 	temp.param[0] = param1;
	// 	temp.param[1] = param2;
	// 	temp.param[2] = param3;
	// 	temp.param[3] = param4;
	// 	temp.param[4] = param5;
	// 	temp.param[5] = param6;
	// 	temp.param[6] = param7;
	// 	temp.param[7] = param8;
	// 	temp.param[8] = param9;
	// //	snprintf(cmd, sizeof cmd, "/sbin/insmod /home/lglei/lglei/MTDResearch/implementation/laptop-home/change_seccomplist/change-seccomp.ko pid=%d sock_fprog0=%s sock_fprog1=%s sock_fprog2=%s sock_fprog3=%s sock_fprog4=%s sock_fprog5=%s sock_fprog6=%s sock_fprog7=%s sock_fprog8=%s lenf=%d",pid,param1,param2,param3,param4,param5,param6,param7,param8,param9,len);
	// }
	// //printf("cmd=%s\r\n",cmd);
	// //system("/bin/dmesg -C");
	// //system("/sbin/rmmod change-seccomp");
	// //system(cmd);
	// //system("/bin/dmesg");
}

int flag = 0;



void identify_running(int pid_num){
    clock_t t;

    int status;
    struct user_regs_struct regs;

    if(ptrace(PTRACE_ATTACH, pid_num, NULL, NULL) == -1 )
    {
        fprintf(stderr, "ptrace(PTRACE_ATTACH) failed\n");
        exit(1);
    }

	int last_syscall_num = -1;
    while(1) {
        if (flag == 0){
            waitpid(pid_num, &status, 0);
       
            if(WIFEXITED(status)){
                break;
            }
            ptrace(PTRACE_GETREGS, pid_num, NULL, &regs);
            if(last_syscall_num == regs.orig_rax){
				//printf("SPEAKER: syscall %s return\n", map[regs.orig_rax]);
				last_syscall_num = -1;
			}else{
				printf("SPEAKER: syscall %s\n", map[regs.orig_rax]);
				last_syscall_num = regs.orig_rax;
			}

			
			//printf("%lld\n", regs.orig_rax);

            if (regs.orig_rax == 7){
                flag = 1;
            }
            ptrace(PTRACE_SYSCALL, pid_num, 0, 0);
        }
        else{
            printf("SPEAKER: only system calls that wait for request\n");
            sleep(5);
            waitpid(pid_num, &status, WNOHANG);
       
            ptrace(PTRACE_GETREGS, pid_num, NULL, &regs);
            if (regs.orig_rax != 7){
                flag = 0;
            }
            else{
                printf("SPEAKER: [Phase identification] RUNNING\n");
                ptrace(PTRACE_DETACH, pid_num, 0, 0);
                return;
            }
            
        }
        
    }
}


int main(int argc, char *argv[]) {
	
	// boot with seccomp

    char *run_cmd = "docker run -p 3306:3306 --security-opt \
    seccomp:../Profile/booting.json \
    -e MYSQL_ROOT_PASSWORD=123 -d percona";

	printf("SPEAKER: [Phase identification] STARTUP\n");


    FILE *fp1;
    char path1[1035];
    fp1 = popen(run_cmd, "r");
    if (fp1 == NULL){
        printf("Failed to run command\n");
        exit(1);
    }

    fgets(path1, sizeof(path1), fp1);

    pclose(fp1);

    //printf("Container ID: %s", path1);

    char *container_id = malloc(11);
    strncpy(container_id, path1, 10);
    //printf("Container ID: %s", container_id);



    FILE *fp2;
    char path2[1035];
    char *shim_cmd = malloc(1000);
    strcpy(shim_cmd, "ps -ef | grep ");
    strcat(shim_cmd, container_id);
    strcat(shim_cmd, " | head -1 | awk '{print $2}'");
    //printf("\nshim_cmd: %s\n", shim_cmd);
    fp2 = popen(shim_cmd, "r");
    if (fp2 == NULL){
        printf("Failed to run command\n");
        exit(1);
    }

    fgets(path2, sizeof(path2), fp2);

    pclose(fp2);

    //printf("shim pid: %s size: %d\n", path2, strlen(path2));
    char *shim_pid = malloc(strlen(path2));
    strncpy(shim_pid, path2, strlen(path2)-1);
    shim_pid[strlen(path2)-1] = '\0';
    //printf("start shim pid: %s\n111 end%d", shim_pid, strlen(shim_pid));

    // get pid

    FILE *fp;
    char *pidof_cmd = malloc(1000);
    strcpy(pidof_cmd, "ps -ef | grep ");
    strcat(pidof_cmd, shim_pid);
    strcat(pidof_cmd, " | grep mysqld | head -1 | awk '{print $2}'");
    char path[1035];
    //printf("\npidof_cmd: %s\n", pidof_cmd);
    fp = popen(pidof_cmd, "r");
    if (fp == NULL){
        printf("Failed to run command\n");
        exit(1);
    }

    fgets(path, sizeof(path), fp);
    //printf("***%s***%d", path, strlen(path));

    pclose(fp);

    char *pid_1 = malloc(strlen(path)-1);
    strncpy(pid_1, path, strlen(path)-1);
    int pid = atoi(pid_1);

    //printf("***%d***\n", atoi(pid_1));


    // identify running point and send whitelist
    identify_running(pid);
    prepare_filter(pid, "../Profile/running", 3);


    // send shutdown whitelist in advance
	prepare_filter(pid, "../Profile/shutdown", 4);
	return 0;

}
