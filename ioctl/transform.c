#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/seccomp.h>
#include <linux/security.h>
#include <linux/capability.h>
#include <linux/thread_info.h>
#include <objsec.h>

#include "tsu.h"
#include "log.h"
#include "ioctl_handler.h"

static struct group_info root_groups = { .usage = ATOMIC_INIT(2) };

static int transive_to_context(const char *context)
{
	struct cred *cred;
	struct task_security_struct *tsec;
	u32 sid;
	int error;

	cred = (struct cred *)__task_cred(current);

	tsec = cred->security;
	if (!tsec) {
		pr_err("tsec == NULL!\n");
		return -ENOKEY;
	}

	error = security_secctx_to_secid(context, strlen(context), &sid);
	if (error) {
		pr_info("security_secctx_to_secid %s -> sid: %d, error: %d\n",
			context, sid, error);
		return error;
	}

	tsec->sid = sid;
	tsec->exec_sid = sid;
	tsec->create_sid = sid;
	tsec->keycreate_sid = sid;
	tsec->sockcreate_sid = sid;
	return error;
}

static void setup_groups(struct cred *cred)
{
	if (cred->group_info)
		put_group_info(cred->group_info);
	cred->group_info = get_group_info(&root_groups);
}

static int transform(const char *se_context)
{
	struct cred *cred;
	struct task_struct *task = current;
	int rc;

	rc = transive_to_context(se_context);
	if (rc) {
		pr_err("Transive domain failed.\n");
		return rc;
	}

	cred = (struct cred *)__task_cred(task);

	if (cred->euid.val == 0) {
		pr_warn("Already root, don't escape!\n");
		return 0;
	}

	cred->uid.val = 0;
	cred->suid.val = 0;
	cred->euid.val = 0;
	cred->fsuid.val = 0;

	cred->gid.val = 0;
	cred->fsgid.val = 0;
	cred->sgid.val = 0;
	cred->egid.val = 0;


	// setup capabilities
	cred->cap_effective = CAP_FULL_SET;
	cred->cap_inheritable = CAP_FULL_SET;
	cred->cap_permitted = CAP_FULL_SET;
	cred->cap_bset = CAP_FULL_SET;
	cred->cap_ambient = CAP_FULL_SET;

#ifdef CONFIG_SECCOMP
#if defined(CONFIG_GENERIC_ENTRY)
	clear_task_syscall_work(task, SECCOMP);
#else
	clear_thread_flag(TIF_SECCOMP);
#endif
	task->seccomp.mode = SECCOMP_MODE_DISABLED;
	seccomp_filter_release(task);
#endif

	setup_groups(cred);

	return 0;
}

int handle_transform(unsigned long ioctl_param)
{
	struct tsu_string *context_str;
	char *se_context;
	int rc;

	context_str = memdup_user((void __user *)ioctl_param,
				  sizeof(struct tsu_string));
	if (IS_ERR(context_str))
		return PTR_ERR(context_str);

	se_context = strndup_user(context_str->ptr, context_str->len);
	if (IS_ERR(se_context)) {
		kfree(context_str);
		return PTR_ERR(se_context);
	}

	rc = transform(se_context);
	kfree(se_context);
	return rc;
}
