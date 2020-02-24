/*
 * NOTE: This example is works on x86 and powerpc.
 * Here's a sample kernel module showing the use of kprobes to dump a
 * stack trace and selected registers when _do_fork() is called.
 *
 * For more information on theory of operation of kprobes, see
 * Documentation/kprobes.txt
 *
 * You will see the trace data in /var/log/messages and on the console
 * whenever _do_fork() is invoked to create a new process.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include "utils.h"
#define MAX_SYMBOL_LEN	64
static char symbol[MAX_SYMBOL_LEN] = "prepare_signal";
//static char symbol[MAX_SYMBOL_LEN] = "get_signal";
module_param_string(symbol, symbol, sizeof(symbol), 0644);


extern uint8_t* g_shutdown_bpf_code;
extern int g_len_shutdown;
extern int pid;

/* For each probe you need to allocate a kprobe structure */
static struct kprobe kp = {
	.symbol_name	= symbol,
};

extern struct bpf_prog *g_new;
extern struct task_struct *g_tsk;

/* kprobe pre_handler: called just before the probed instruction is executed */
static int handler_pre(struct kprobe *p, struct pt_regs *regs) {

	// pr_info("<%s> pre_handler: p->addr = 0x%p, ip = %lx, flags = 0x%lx\n",
	// 	, p->addr, regs->ip, regs->flags);

	struct task_struct* task = regs->si;

	if(task->pid == pid && regs->di == 15){
		printk("SPEAKER: receive a signal <no:%d> from <%s>\n", regs->di, current->comm);
		printk("SPEAKER: identify SHUTDOWN phase\n");
		// printk("SPEAKER: <%s> send p->rdi = %ld, p->rsi = %ld, p->rdx = %ld\n",
		// 	current->comm, regs->di, task->pid, regs->dx);
		
		change_process_seccomp(g_new, g_tsk);
	}


	/* A dump_stack() here will give a stack backtrace */
	return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */
static void handler_post(struct kprobe *p, struct pt_regs *regs,
				unsigned long flags) {
	// pr_info("<%s> post_handler: p->addr = 0x%p, flags = 0x%lx\n",
	// 	p->symbol_name, p->addr, regs->flags);
}

/*
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 */
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	pr_info("fault_handler: p->addr = 0x%p, trap #%dn", p->addr, trapnr);
	/* Return 0 because we don't handle the fault. */
	return 0;
}

int kprobe_init(void) {
	int ret;
	kp.pre_handler = handler_pre;
	kp.post_handler = handler_post;
	kp.fault_handler = handler_fault;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("register_kprobe failed, returned %d\n", ret);
		return ret;
	}
	pr_info("Planted kprobe at %p\n", kp.addr);
	return 0;
}

void kprobe_exit(void){
	unregister_kprobe(&kp);
	pr_info("kprobe at %p unregistered\n", kp.addr);
}

