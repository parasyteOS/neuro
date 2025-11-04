#include <linux/lsm_hooks.h>
#include <linux/fs.h>
#include <linux/anon_inodes.h>
#include <linux/timekeeping.h>
#include <linux/stringify.h>

#include "core.h"
#include "log.h"
#include "tsu.h"
#include "ecdsa.h"
#include "handler.h"

static inline bool is_isolated_uid(uid_t uid)
{
#define FIRST_ISOLATED_UID 99000
#define LAST_ISOLATED_UID 99999
#define FIRST_APP_ZYGOTE_ISOLATED_UID 90000
#define LAST_APP_ZYGOTE_ISOLATED_UID 98999
	uid_t appid = uid % 100000;
	return (appid >= FIRST_ISOLATED_UID && appid <= LAST_ISOLATED_UID) ||
	       (appid >= FIRST_APP_ZYGOTE_ISOLATED_UID &&
		appid <= LAST_APP_ZYGOTE_ISOLATED_UID);
}

struct sig_payload {
	u8 *signature;
	u32 signature_size;
};

struct dynamic_digest {
	u64 secs;
	u32 pid;
	u32 uid;
};

static int verify_signature(void __user *sig)
{
	int ret = 1;
	struct sig_payload *payload;
	time64_t secs = ktime_get_real_seconds();
	struct dynamic_digest digest = {
	  .secs = secs - secs % 5,
	  .pid = current->pid,
	  .uid = current_uid().val,
	};

	payload = memdup_user(sig, sizeof(struct sig_payload));
	if (IS_ERR(payload)) {
		pr_err("Failed to copy payload");
		return ret;
	}

	payload->signature = memdup_user((void __user *)payload->signature, payload->signature_size);
	if (IS_ERR(payload->signature)) {
		pr_err("Failed to copy signature");
		goto free_payload;
	}

	ret = ecdsa_verify_signature((u8 *)&digest, sizeof(digest),
     			 		payload->signature, payload->signature_size);

	if (ret) {
		pr_err("Signature verification failed: %d", ret);
	} else {
		pr_info("Signature verification succeed.");
	}

	kfree(payload->signature);
free_payload:
	kfree(payload);
	return ret;
}

int tsu_handle_prctl(int option, unsigned long sig, unsigned long cmd,
		     unsigned long arg, unsigned long reply)
{
	int _reply = -EINVAL;

	if (TERMINAL_SU_OPTION != option)
		return 0;

	// always ignore isolated app uid
	if (is_isolated_uid(current_uid().val))
		return 0;

	if (verify_signature((void __user *)sig))
		return 0;

	switch (cmd) {
	case CMD_SEPOL_GETFD:
		_reply = handle_selinux_policy_getfd(arg);
		break;
	case CMD_TRANSFORM:
		_reply = handle_transform(arg);
		break;
	default:
		pr_err("Unknown command: %d\n", cmd);
	}

	if (copy_to_user((void __user *)reply, &_reply, sizeof(_reply))) {
		pr_err("prctl reply error.");
	}
	return 0;
}


static int tsu_task_prctl(int option, unsigned long arg2, unsigned long arg3,
			  unsigned long arg4, unsigned long arg5)
{
	tsu_handle_prctl(option, arg2, arg3, arg4, arg5);
	return -ENOSYS;
}

static struct security_hook_list tsu_hooks[] = {
	LSM_HOOK_INIT(task_prctl, tsu_task_prctl),
};

void __init tsu_core_init(void)
{
	pr_info("initialize lsm hooks.");
	security_add_hooks(tsu_hooks, ARRAY_SIZE(tsu_hooks), "tsu");
	pr_info("initialize ecdsa.");
	if (init_ecdsa(__stringify(TSU_PUB_KEY)))
		pr_err("Failed to initialize ecdsa.");
}

void tsu_core_exit(void)
{
}
