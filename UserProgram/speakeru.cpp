/* c++ header */
#include <iostream>
#include <fstream>
#include <map>
#include <string>
#include <vector>

/* c header */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

/* sys header*/
#include <seccomp.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <wait.h>
#include <pwd.h>
#include "syscall_table.h"

#define TMP_PATH "./seccomp_filter.bpf"

#define SETUP_PID 3
#define SET_BOOTING 4
#define SET_RUNNING 5
#define SET_SHUTDOWN 6
#define TO_BOOTING 7
#define TO_RUNNING 8

std::map<std::string, int> name_to_num;

void identify_running(int pid);
int prepare_filter(const char *filepath_name, int cmd, int fd);


int main(int argc, char *argv[]) {
	/* boot container with seccomp */
    const char *run_cmd = "docker run -p 3306:3306 \
    -e MYSQL_ROOT_PASSWORD=mysql -d percona";

    /* init map, syscall name to syscall number */
    for(int i = 0; i < sizeof(syscall_table) / sizeof(char*); i++)
        name_to_num[syscall_table[i]] = i;
    
    /* setup bpf prog */
	int chrdev_fd = open("/dev/speaker", O_RDWR);
	if(chrdev_fd == -1){
		printf("Failed to open device!\n");
		return -1;
	}
    prepare_filter("../Profile/booting", SET_BOOTING, chrdev_fd);
    prepare_filter("../Profile/running", SET_RUNNING, chrdev_fd);
    prepare_filter("../Profile/shutdown", SET_SHUTDOWN, chrdev_fd);



    std::cout << "SPEAKER: [Phase identification] STARTUP" << std::endl;

    /* get the container id */
    char container_id[11] = {'\0'};
    FILE* container_fd = popen(run_cmd, "r");
    if (container_fd == NULL){
        std::cout << "Failed to run command" << std::endl;
        return -1;
    }
    fgets(container_id, sizeof(container_id), container_fd);
    pclose(container_fd);

    /* get the pid of shim process */
    char shim_cmd[100] = {'\0'};
    char shim_pid[10] = {'\0'};
    sprintf(shim_cmd, "ps -ef | grep %s | head -1 | awk '{print $2}'", container_id);
    FILE* shim_fd = popen(shim_cmd, "r");
    if(shim_fd == NULL){
        std::cout << "Failed to run command" << std::endl;
        return -1;
    }
    fgets(shim_pid, sizeof(shim_pid), shim_fd);
    shim_pid[strlen(shim_pid)-2] = '\0';
    pclose(shim_fd);

    /* get the pid of tracee */
    char target_pid_cmd[100] = {'\0'};
    char target_pid[10] = {'\0'};
    sprintf(target_pid_cmd, "ps -ef | grep %s | grep mysqld | head -1 | awk '{print $2}'", shim_pid);
    FILE* target_pid_fd = popen(target_pid_cmd, "r");
    if (target_pid_fd == NULL){
        std::cout << "Failed to run command" << std::endl;
        return -1;
    }
    fgets(target_pid, sizeof(target_pid), target_pid_fd);
    pclose(target_pid_fd);
    int pid = atoi(target_pid);
    
    /* update booting list and pid*/
    ioctl(chrdev_fd, SETUP_PID, pid);
    ioctl(chrdev_fd, TO_BOOTING, 0);

    /* identify running point and send whitelist */
    identify_running(pid);
	ioctl(chrdev_fd, TO_RUNNING, 0);

    return 0;
}


/* Two input argvs: System call list file path; Pid of the first container process */
int prepare_filter(const char *filepath_name, int cmd, int fd){
	//parse the arguments
	int ret = -1;

	/* parse the input syscall file */
	/* default action: kill (will receive a signal no.31)*/
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL)
		return -1;

	if (seccomp_arch_exist(ctx, SCMP_ARCH_X86_64) == -EEXIST) {
		ret = seccomp_arch_add(ctx, SCMP_ARCH_X86_64);
		if (ret != 0){	
            seccomp_release(ctx);
	        return -1;
        }
	}
	if (seccomp_arch_exist(ctx, SCMP_ARCH_X86) == -EEXIST) {
		ret = seccomp_arch_add(ctx, SCMP_ARCH_X86);
		if (ret != 0){
        	seccomp_release(ctx);
	        return -1;
        }
	}
	if (seccomp_arch_exist(ctx, SCMP_ARCH_X32) == -EEXIST) {
		ret = seccomp_arch_add(ctx, SCMP_ARCH_X32);
		if (ret != 0){
        	seccomp_release(ctx);
	        return -1;
        }
	}

    std::ifstream whitelist_file;
    whitelist_file.open(filepath_name);
    if (!whitelist_file.is_open()){
        std::cout << "Failed to open file: " << filepath_name << std::endl;
        seccomp_release(ctx);
	    return -1;
    }

    std::string str;
    while (getline(whitelist_file, str)) {
        std::map<std::string, int>::iterator iter = name_to_num.find(str);
        if (iter != name_to_num.end()){
			ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, (*iter).second, 0);
			if (ret < 0){
            	seccomp_release(ctx);
	            return -1;
            }
        } else
            std::cout << "Unknown syscall name: " << str << std::endl;
	}
    
    int filter_fd = open(TMP_PATH, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	if (filter_fd == -1) {
        std::cout << "Failed to open file: " << TMP_PATH << std::endl;
        seccomp_release(ctx);
        return -1;
	}

    /* should be used to seccomp_load(ctx) */
	ret = seccomp_export_bpf(ctx, filter_fd);
	if (ret < 0) {
        std::cout << "Failed to export BPF filter" << std::endl;
		close(filter_fd);
        seccomp_release(ctx);
        return -1;
	}

	struct stat st;
	if(fstat(filter_fd, &st) != 0) {
        close(filter_fd);
    	seccomp_release(ctx);
        return -1; 
    }

    uint8_t* p_bpf = (uint8_t*)mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, filter_fd, 0);
    if(p_bpf == NULL){
        std::cout << "Failed to mmap file " << TMP_PATH << std::endl;
        close(filter_fd);
    	seccomp_release(ctx);
        return -1;
    }

    struct sock_fprog fprog = {
        .len = st.st_size / sizeof(struct sock_filter),
        .filter = (struct sock_filter *)p_bpf,
    };
    
    /* pass bpf code to kernel module */
	ioctl(fd, cmd, &fprog);
	munmap(p_bpf, st.st_size);
    close(filter_fd);
    remove(TMP_PATH);

	return 0;
}



void identify_running(int pid){
    int status;
    struct user_regs_struct regs;
    int flag = 0;
    
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1 ) {
        std::cout << "Failed to attach process no." << pid << std::endl;
        exit(-1);
    }

    /* this values is used to distinguish syscall entry or exit */
	int last_syscall_num = -1;
    while(1) {
        if (flag == 0){
            waitpid(pid, &status, 0);
            if (WIFEXITED(status))
                break;

            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            if (last_syscall_num == regs.orig_rax)
				last_syscall_num = -1;
			else {
                std::cout << "SPEAKER: syscall " << syscall_table[regs.orig_rax] << std::endl;
				last_syscall_num = regs.orig_rax;
			}

            if (regs.orig_rax == 7)
                flag = 1;

            ptrace(PTRACE_SYSCALL, pid, 0, 0);
        } else {
            std::cout << "SPEAKER: only system calls that wait for request" << std::endl;
            sleep(5);
            waitpid(pid, &status, WNOHANG);

            /* there is one corner case, the syscall sequence is as follows:
             * poll (2s) read (2s) poll (here we execute)
             * so it is the right entry point?
             */
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            if (regs.orig_rax != 7)
                flag = 0;
            else {
                std::cout << "SPEAKER: [Phase identification] RUNNING" << std::endl; 
                ptrace(PTRACE_DETACH, pid, 0, 0);
                return;
            }
        }
    }
}


