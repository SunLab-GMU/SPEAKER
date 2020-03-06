#include <linux/module.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/pid.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/ptrace.h>
#include <linux/security.h>
#include <linux/tracehook.h>
#include <linux/bpf.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/gfp.h>
#include <linux/err.h>
#include <linux/bug.h>
#include <linux/kernel.h>
#include <linux/if_vlan.h>
#include <linux/netdevice.h>
#include <linux/mm.h>
#include <linux/fcntl.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/if_packet.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/flow_dissector.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <asm/uaccess.h>
#include <asm/unaligned.h>
#include <linux/ratelimit.h>
#include <linux/if_vlan.h>
#include <uapi/linux/bpf_common.h>
#include <linux/skbuff.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/igmp.h>
#include <uapi/linux/dccp.h>
#include <linux/sctp.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <asm/traps.h>
#include <asm/desc_defs.h>
#include <linux/moduleparam.h>
#include <linux/delay.h>
#include<linux/cdev.h>
#include<linux/fs.h>
#include<linux/kdev_t.h>
#include<linux/string.h>
#include <linux/mm_types.h>
#include <linux/slab.h>
#include <asm/smp.h>
#include "utils.h"


/* global variants */
/* process information of target app*/
int g_pid = 0;
struct task_struct *g_tsk = NULL;

/* bpf programs for different stages */
struct bpf_prog *g_booting_prog = NULL, *g_running_prog = NULL, *g_shutdown_prog = NULL;

/* for output logs */ 
int phase_flag = 0;
int state = 0;

int change_process_seccomp(struct bpf_prog* new_prog, struct task_struct *tsk) {
	if(new_prog != NULL && tsk->seccomp.filter != NULL) {
		struct seccomp_filter* filter = tsk->seccomp.filter;
		struct bpf_prog* org_prog = filter->prog;

		filter->prog = new_prog;
		/* free memory*/
		bpf_prog_destroy(org_prog);
		if(phase_flag == 0){
			printk("SPEAKER: BOOTING whitelist updated successfully!\n");
            phase_flag = 1;
        }
		else if(phase_flag == 1){
			printk("SPEAKER: RUNNING whitelist updated successfully!\n");
		    phase_flag = 2;
        }else{
			printk("SPEAKER: SHUTDOWN whitelist updated successfully!\n");
		    phase_flag = 0;
        }

		return 0;
	}
	return -1;
}

long ioctl(struct file *filep, unsigned int cmd, unsigned long arg){
    struct sock_fprog fprog;
	int ret = 0;

	switch (cmd){
    case SETUP_PID:
        state = SETUP_PID;
        g_pid = (int)arg;
        g_tsk = pid_task(find_vpid(g_pid), PIDTYPE_PID);
        break;
	case SET_BOOTING:
        state = SET_BOOTING;
        copy_from_user(&fprog, (uint8_t*)arg, sizeof(fprog));
        ret = bpf_prog_create_from_user(&g_booting_prog, &fprog, seccomp_check_filter, 0);
        if (ret != 0) {
            printk("SPEAKER: failed to create booting bpf program!\n");
            return ret;
        }
        break;
	case SET_RUNNING:
        state = SET_RUNNING;
        copy_from_user(&fprog, (uint8_t*)arg, sizeof(fprog));
		ret = bpf_prog_create_from_user(&g_running_prog, &fprog, seccomp_check_filter, 0);
        if (ret != 0) {
			printk("SPEAKER: failed to create running bpf program\n");
			return ret;	
		}
        break;
    case SET_SHUTDOWN:
        state = SET_SHUTDOWN;
        copy_from_user(&fprog, (uint8_t*)arg, sizeof(fprog));
        ret = bpf_prog_create_from_user(&g_shutdown_prog, &fprog, seccomp_check_filter, 0);
        if (ret != 0) {
			printk("SPEAKER: failed to create shutdown bpf program\n");
			return ret;	
		}
        break;
    case TO_BOOTING:
        state = TO_BOOTING;
        if(g_tsk != NULL && (g_tsk->seccomp.filter) != NULL && ((g_tsk->seccomp.filter)->prog) != NULL && g_booting_prog != NULL)
            ret = change_process_seccomp(g_booting_prog, g_tsk);
        else{
            printk("SPEAKER: failed to update booting bpf program\n");
            return -1;
        }
        break;
    case TO_RUNNING:
        state = TO_RUNNING;
        if(g_tsk != NULL && (g_tsk->seccomp.filter) != NULL && ((g_tsk->seccomp.filter)->prog) != NULL && g_running_prog != NULL)
            return change_process_seccomp(g_running_prog, g_tsk);
        else{
            printk("SPEAKER: failed to update running bpf program\n");
            return -1;
        }
        break;
    default:
		printk("SPEAKER: Invalid parameter in ioctl\n");
		break;
	}
	
	return 0;
}

int open(struct inode *inode,struct file *file) { return 0; }

ssize_t write(struct file *file, const char __user *usr, size_t len, loff_t *off){ return 0; }

ssize_t read(struct file *file, char __user *usr, size_t len, loff_t *off){ return 0; }

int release(struct inode *inode, struct file *file){ 
    // g_pid = 0;
    // g_tsk = NULL;

    // if(state == SET_SHUTDOWN){
    //     bpf_prog_destroy(g_shutdown_prog);
    //     bpf_prog_destroy(g_running_prog);
    //     bpf_prog_destroy(g_booting_prog);
    // }

    // if(state == SET_RUNNING){
    //     bpf_prog_destroy(g_booting_prog);
    //     bpf_prog_destroy(g_running_prog);
    // }

    // if(state == SET_BOOTING){
    //     bpf_prog_destroy(g_booting_prog);
    // }

    // if(state == SET_BOOTING){
    //     bpf_prog_destroy(g_shutdown_prog);
    //     bpf_prog_destroy(g_running_prog);
    // }

    // if(state == SET_RUNNING){
    //     bpf_prog_destroy(g_shutdown_prog);
    // }

    // g_booting_prog = NULL;
    // g_running_prog = NULL;
    // g_shutdown_prog = NULL;
    // phase_flag = 0;
    // state = 0;

    return 0; 
}



struct file_operations fops={
     .owner = THIS_MODULE,
     .open = open,
     .write = write,
     .read = read,
     .release = release,
     .unlocked_ioctl = ioctl,
};


struct cdev chrdev;
dev_t dev_no;

int __init init_speaker_module(void) {
	u_int32_t TestMajor = 0;
    u_int32_t TestMinor = 0;
    int ret = 0;
    
    dev_no = MKDEV(TestMajor,TestMinor);
    if (dev_no > 0)
        ret = register_chrdev_region(dev_no, 1, "speaker_driver");    
    else
        alloc_chrdev_region(&dev_no, 0, 1,"speaker_driver");
    if (ret < 0)
        return ret;

    cdev_init(&chrdev, &fops);
    chrdev.owner = THIS_MODULE;
    cdev_add(&chrdev, dev_no, 1);

	kprobe_init();

    return 0;
}


void __exit cleanup_speaker_module(void) {
    unregister_chrdev_region(dev_no, 1);
    cdev_del(&chrdev);
	kprobe_exit();
}





/**
 *	seccomp_check_filter - verify seccomp filter code
 *	@filter: filter to verify
 *	@flen: length of filter
 *
 * Takes a previously checked filter (by bpf_check_classic) and
 * redirects all filter code that loads struct sk_buff data
 * and related data through seccomp_bpf_load.  It also
 * enforces length and alignment checking of those loads.
 *
 * Returns 0 if the rule set is legal or -EINVAL if not.
 */
int seccomp_check_filter(struct sock_filter *filter, unsigned int flen) {
	int pc;
	for (pc = 0; pc < flen; pc++) {
		struct sock_filter *ftest = &filter[pc];
		u16 code = ftest->code;
		u32 k = ftest->k;

		switch (code) {
		case BPF_LD | BPF_W | BPF_ABS:
			ftest->code = BPF_LDX | BPF_W | BPF_ABS;
			/* 32-bit aligned and not out of bounds. */
			if (k >= sizeof(struct seccomp_data) || k & 3)
				return -EINVAL;
			continue;
		case BPF_LD | BPF_W | BPF_LEN:
			ftest->code = BPF_LD | BPF_IMM;
			ftest->k = sizeof(struct seccomp_data);
			continue;
		case BPF_LDX | BPF_W | BPF_LEN:
			ftest->code = BPF_LDX | BPF_IMM;
			ftest->k = sizeof(struct seccomp_data);
			continue;
		/* Explicitly include allowed calls. */
		case BPF_RET | BPF_K:
		case BPF_RET | BPF_A:
		case BPF_ALU | BPF_ADD | BPF_K:
		case BPF_ALU | BPF_ADD | BPF_X:
		case BPF_ALU | BPF_SUB | BPF_K:
		case BPF_ALU | BPF_SUB | BPF_X:
		case BPF_ALU | BPF_MUL | BPF_K:
		case BPF_ALU | BPF_MUL | BPF_X:
		case BPF_ALU | BPF_DIV | BPF_K:
		case BPF_ALU | BPF_DIV | BPF_X:
		case BPF_ALU | BPF_AND | BPF_K:
		case BPF_ALU | BPF_AND | BPF_X:
		case BPF_ALU | BPF_OR | BPF_K:
		case BPF_ALU | BPF_OR | BPF_X:
		case BPF_ALU | BPF_XOR | BPF_K:
		case BPF_ALU | BPF_XOR | BPF_X:
		case BPF_ALU | BPF_LSH | BPF_K:
		case BPF_ALU | BPF_LSH | BPF_X:
		case BPF_ALU | BPF_RSH | BPF_K:
		case BPF_ALU | BPF_RSH | BPF_X:
		case BPF_ALU | BPF_NEG:
		case BPF_LD | BPF_IMM:
		case BPF_LDX | BPF_IMM:
		case BPF_MISC | BPF_TAX:
		case BPF_MISC | BPF_TXA:
		case BPF_LD | BPF_MEM:
		case BPF_LDX | BPF_MEM:
		case BPF_ST:
		case BPF_STX:
		case BPF_JMP | BPF_JA:
		case BPF_JMP | BPF_JEQ | BPF_K:
		case BPF_JMP | BPF_JEQ | BPF_X:
		case BPF_JMP | BPF_JGE | BPF_K:
		case BPF_JMP | BPF_JGE | BPF_X:
		case BPF_JMP | BPF_JGT | BPF_K:
		case BPF_JMP | BPF_JGT | BPF_X:
		case BPF_JMP | BPF_JSET | BPF_K:
		case BPF_JMP | BPF_JSET | BPF_X:
			continue;
		default:
			return -EINVAL;
		}
	}
	return 0;
}




module_init(init_speaker_module);
module_exit(cleanup_speaker_module);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("lglei <lglei@wm.edu>");
MODULE_DESCRIPTION("process monitoring module");

