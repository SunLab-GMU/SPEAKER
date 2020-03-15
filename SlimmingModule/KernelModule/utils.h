#ifndef _UTILS_HEADER_
#define _UTILS_HEADER_
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



#define SETUP_PID 3
#define SET_BOOTING 4
#define SET_RUNNING 5
#define SET_SHUTDOWN 6
#define TO_BOOTING 7
#define TO_RUNNING 8

int kprobe_init(void);
void kprobe_exit(void);
int init_speaker(void* bpf_code, int length);
int seccomp_check_filter(struct sock_filter *filter, unsigned int flen);
int change_process_seccomp(struct bpf_prog * prog, struct task_struct *tsk);


struct seccomp_filter {
	refcount_t usage;
    bool log;
	struct seccomp_filter *prev;
	struct bpf_prog *prog;
};


#endif
