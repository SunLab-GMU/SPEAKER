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
#include <iostream>
#include <map>
#include <string>
#include <vector>
#include <sys/mman.h>
#include <pwd.h>

using namespace std;

#define TMP_PATH "./seccomp_filter.bpf"
typedef struct request{
	int pid;
	int lenf;
	uint8_t* bpf_code;
} REQUEST;

map<string, int> name_to_num;

/* Two input argvs: System call list file path; Pid of the first container process */
int prepare_filter(int pid, char *filepath_name, int cmd){
	//parse the arguments
	int ret = -1;

	int chrdev_fd = open("/dev/chrdev", O_RDWR);
	if(chrdev_fd == -1){
		printf("Failed to open device!\n");
		return -1;
	}

	/* parse the input syscall file */
	/* default action: kill (will receive a signal no.31)*/
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL)
		goto error_exit;

	if (seccomp_arch_exist(ctx, SCMP_ARCH_X86_64) == -EEXIST) {
		ret = seccomp_arch_add(ctx, SCMP_ARCH_X86_64);
		if (ret != 0)
			goto error_exit;
	}
	if (seccomp_arch_exist(ctx, SCMP_ARCH_X86) == -EEXIST) {
		ret = seccomp_arch_add(ctx, SCMP_ARCH_X86);
		if (ret != 0)
			goto error_exit;
	}
	if (seccomp_arch_exist(ctx, SCMP_ARCH_X32) == -EEXIST) {
		ret = seccomp_arch_add(ctx, SCMP_ARCH_X32);
		if (ret != 0)
			goto error_exit;
	}

    ifstream whitelist_file(filepath_name)
    if (!whitelist_file.good()){
        cout << "Failed to open file: " << filepath_name << endl;
        goto error_exit;
    }

    string str;
    while (getline(whitelist_file , str, '\n')) {
        map<string, int>::iterator iter = name_to_num.find(str);
        if(iter != name_to_num.end()){
			ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, *iter, 0);
			if (ret < 0)
				goto error_exit;
        } else
            cout<< "Unknown syscall name: " << str << endl;
	}

	int filter_fd = open(TMP_PATH, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	if (filter_fd == -1) {
        cout << "Failed to open file: " << TMP_PATH << endl;
		goto error_exit;
	}

    /* should be used to seccomp_load(ctx) */
	ret = seccomp_export_bpf(ctx, filter_fd);
	if (ret < 0) {
        cout << "Failed to export BPF filter" << endl;
		close(filter_fd);
		goto error_exit;
	} else
	    goto normal_exit;


error_exit:
	seccomp_release(ctx);
    remove(TMP_PATH);
	return -1;

normal_exit:
	struct stat st;
	if(fstat(filter_fd, &st) != 0) {
        close(filter_fd);
    	seccomp_release(ctx);
        return -1; 
    }

    uint8_t* p_bpf = (uint8_t*)mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, filter_fd, 0);
    if(p_bpf == nullptr){
        cout << "Failed to mmap file " << path << endl;
        close(filter_fd);
    	seccomp_release(ctx);
        return -1;
    }

	REQUEST request = {
        .pid = pid,
        .lenf = st.st_size / sizeof(struct sock_filter);
        .bpf_code = p_bpf;
    };

    /* pass bpf code to kernel module */
	ioctl(chrdev_fd, cmd, &request);
	munmap(p_bpf, st.st_size);
    remove(TMP_PATH);

	return 0;
}



void identify_running(int pid){
    int status;
    struct user_regs_struct regs;
    int flag = 0;
    
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1 ) {
        cout << "Failed to attach process no." << pid << endl;
        exit(-1);
    }

    /* this values is used to distinguish syscall entry or exit */
	int last_syscall_num = -1;
    while(1) {
        if (flag == 0){
            waitpid(pid_num, &status, 0);
            if (WIFEXITED(status))
                break;

            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            if (last_syscall_num == regs.orig_rax)
				last_syscall_num = -1;
			else {
                cout << "SPEAKER: syscall " << syscall_table[regs.orig_rax] << endl;
				last_syscall_num = regs.orig_rax;
			}

            if (regs.orig_rax == 7)
                flag = 1;

            ptrace(PTRACE_SYSCALL, pid, 0, 0);
        } else {
            cout << "SPEAKER: only system calls that wait for request" << endl;
            sleep(5);
            waitpid(pid, &status, WNOHANG);

            /* there is one corner case, the syscall sequence is as follows:
             * poll (2s) read (2s) poll (here we execute)
             * so it is the right entry point?
             */
            ptrace(PTRACE_GETREGS, pid_num, NULL, &regs);
            if (regs.orig_rax != 7)
                flag = 0;
            else {
                cout << "SPEAKER: [Phase identification] RUNNING" << endl; 
                ptrace(PTRACE_DETACH, pid, 0, 0);
                return;
            }
        }
    }
}


int main(int argc, char *argv[]) {
	/* boot container with seccomp */
    char *run_cmd = "docker run -p 3306:3306 --security-opt \
    seccomp:../Profile/booting.json \
    -e MYSQL_ROOT_PASSWORD=123 -d percona";

    cout << "SPEAKER: [Phase identification] STARTUP" << endl;


    FILE *fp1;
    char path1[1035];
    fp1 = popen(run_cmd, "r");
    if (fp1 == NULL){
        printf("Failed to run command\n");
        exit(1);
    }

    fgets(path1, sizeof(path1), fp1);
    pclose(fp1);

    /* init map, syscall name to syscall number */
    for(int i = 0; i < sizeof(syscall_table); i++)
        name_to_num[syscall_table[i]] = i;





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
