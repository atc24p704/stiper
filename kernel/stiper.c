// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/kernel/stiper.c
 *
 *  Copyright (C) 2024 STIPER
 */
#include <linux/slab.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/sched/mm.h>
#include <linux/sched/user.h>
#include <linux/sched/debug.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/cputime.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/tty.h>
#include <linux/binfmts.h>
#include <linux/coredump.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/ptrace.h>
#include <linux/signal.h>
#include <linux/signalfd.h>
#include <linux/ratelimit.h>
#include <linux/task_work.h>
#include <linux/capability.h>
#include <linux/freezer.h>
#include <linux/pid_namespace.h>
#include <linux/nsproxy.h>
#include <linux/user_namespace.h>
#include <linux/uprobes.h>
#include <linux/compat.h>
#include <linux/cn_proc.h>
#include <linux/compiler.h>
#include <linux/posix-timers.h>
#include <linux/cgroup.h>
#include <linux/audit.h>
#include <linux/sysctl.h>

// #define CREATE_TRACE_POINTS
// #include <trace/events/signal.h>
#include <asm/stiper.h>
#include <asm/param.h>
#include <linux/uaccess.h>
#include <asm/unistd.h>
#include <asm/siginfo.h>
#include <asm/cacheflush.h>
#include <asm/syscall.h>	/* for syscall_get_* */

#ifdef CONFIG_STIPER
static inline bool check_sm_permission(struct meta_info *metainfo)
{
	return true;
}

static inline bool check_sm_info(struct sm_info *sminfo)
{
	/* check if ptr is aligned to page size */
	if (!sminfo || (unsigned long)sminfo->ptr & (PAGE_SIZE - 1))
		return false;

	return true;
}

static inline void prepare_sm_siginfo(int sig, struct kernel_siginfo *info)
{
	clear_siginfo(info);
	info->si_signo = sig;
	info->si_errno = 0;
	info->si_code = SI_USER;
	info->si_pid = task_tgid_vnr(current);
	info->si_uid = from_kuid_munged(current_user_ns(), current_uid());
	info->smreq_ptr = (char *) 0xdeadc0de;
	info->smreq_size = 0xdeadc0de;
}

static int post_proc_info(int sig, struct kernel_siginfo *info, pid_t pid)
{
	int error;
	rcu_read_lock();
	error = kill_pid_info(sig, info, find_vpid(pid));
	rcu_read_unlock();
	return error;
}

static int sm_post_info(int sig, struct kernel_siginfo *info, pid_t pid)
{
	if (pid > 0)
		return post_proc_info(sig, info, pid);

	/* Others are undefined.  Exclude this case to avoid a UBSAN warning */
	return -ESRCH;
}

/**
 *  sys_smreq - send a signal to a process
 *  @pid: the PID of the process
 *  @sminfo: share memory information which want to send
 *  @metainfo: meta information, use to check the permission
 */
SYSCALL_DEFINE3(smreq, pid_t, pid, struct sm_info __user *, sminfo, struct meta_info __user *, metainfo)
{
	struct kernel_siginfo info;

	if (!check_sm_permission(metainfo))
		return -EACCES;
	
	if (!check_sm_info(sminfo))
		return -EINVAL;

	prepare_sm_siginfo(SIGUSR1, &info);

	return sm_post_info(SIGUSR1, &info, pid);

}
#else
SYSCALL_DEFINE0(smreq)
{
	return -ENOSYS;
}
#endif /* CONFIG_STIPER */
