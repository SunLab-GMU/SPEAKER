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
int kprobe_init(void);

void kprobe_exit(void);

int init_speaker(void* bpf_code, int length);


int seccomp_check_filter(struct sock_filter *filter, unsigned int flen);
int bpf_prog_create_lglei(struct bpf_prog **pfp, struct sock_fprog *fprog,
			      bpf_aux_classic_check_t trans);
struct bpf_prog *bpf_prepare_filter(struct bpf_prog *fp,
					   bpf_aux_classic_check_t trans);
int bpf_check_classic(const struct sock_filter *filter,
			     unsigned int flen);
void __bpf_prog_release(struct bpf_prog *prog);
struct bpf_prog *bpf_migrate_filter(struct bpf_prog *fp);
int bpf_convert_filter(struct sock_filter *prog, int len,
			      struct bpf_insn *new_prog, int *new_len);
void bpf_release_orig_filter(struct bpf_prog *fp);
bool chk_code_allowed(u16 code_to_probe);
int check_load_and_stores(const struct sock_filter *filter, int flen);
bool convert_bpf_extensions(struct sock_filter *fp,
				   struct bpf_insn **insnp);
u32 convert_skb_access(int skb_field, int dst_reg, int src_reg,
			      struct bpf_insn *insn_buf);
u64 __skb_get_nlattr(u64 ctx, u64 a, u64 x, u64 r4, u64 r5);
u64 __skb_get_pay_offset(u64 ctx, u64 a, u64 x, u64 r4, u64 r5);
u64 __skb_get_nlattr_nest(u64 ctx, u64 a, u64 x, u64 r4, u64 r5);
u64 __get_raw_cpu_id(u64 ctx, u64 a, u64 x, u64 r4, u64 r5);
u64 __get_random_u32(u64 ctx, u64 a, u64 x, u64 r4, u64 r5);
u64 __bpf_call_base(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);
void bpf_jit_compile(struct bpf_prog *prog);
u32 skb_get_poff(const struct sk_buff *skb);
u32 __skb_get_poff(const struct sk_buff *skb, void *data,
		   const struct flow_keys *keys, int hlen);

int change_process_seccomp(struct bpf_prog * prog, struct task_struct *tsk);

void print_data_for_process(struct task_struct *my_current);

#endif
