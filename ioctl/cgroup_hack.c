#include <linux/cgroup.h>

#include "tsu.h"
#include "log.h"
#include "ioctl_handler.h"

static int override_top_cgroup_bpf_flags(struct cgroup *cgrp,
					 enum cgroup_bpf_attach_type btype)
{
	struct cgroup *target = NULL;
	struct cgroup *parent = cgrp;
	u32 flags;

	do {
		target = parent;
		parent = cgroup_parent(target);
	} while (parent != NULL);

	flags = target->bpf.flags[btype];
	target->bpf.flags[btype] = flags | BPF_F_ALLOW_MULTI;
	return 0;
}

int handle_cgroup_hack(unsigned long ioctl_param)
{
	struct tsu_cgrp_hack_param *param;
	struct cgroup *cgrp;
	int rc = -EINVAL;

	param = memdup_user((void __user *)ioctl_param,
			    sizeof(struct tsu_cgrp_hack_param));

	if (IS_ERR(param))
		return PTR_ERR(param);

	if (param->cgrp_bpf_attach_type <= CGROUP_BPF_ATTACH_TYPE_INVALID
	    || param->cgrp_bpf_attach_type >= MAX_CGROUP_BPF_ATTACH_TYPE) {
		rc = -EINVAL;
		goto free;
	}

	cgrp = cgroup_get_from_fd(param->cgrp_fd);
	if (IS_ERR(cgrp)) {
		pr_err("Cannot get cgroup from fd.");
		rc = PTR_ERR(cgrp);
		goto free;
	}
	
	rc = override_top_cgroup_bpf_flags(cgrp, param->cgrp_bpf_attach_type);
	cgroup_put(cgrp);
free:
	kfree(param);
	return rc;
}
