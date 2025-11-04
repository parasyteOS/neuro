#include <linux/fs.h>
#include <linux/anon_inodes.h>
#include <ss/services.h>

#include "tsu.h"
#include "log.h"
#include "handler.h"

struct policy_load_memory {
	size_t len;
	void *data;
};

static ssize_t sel_read_policy(struct file *filp, char __user *buf,
			       size_t count, loff_t *ppos)
{
	struct policy_load_memory *plm = filp->private_data;
	BUG_ON(!plm);
	return simple_read_from_buffer(buf, count, ppos, plm->data, plm->len);
}

static ssize_t sel_write_policy(struct file *filp, const char __user *buf,
			      size_t count, loff_t *ppos)

{
	struct selinux_load_state load_state;
	struct policy_load_memory *plm = filp->private_data;
	ssize_t length;
	void *data = NULL;

	BUG_ON(!plm);

	mutex_lock(&selinux_state.policy_mutex);

	/* No partial writes. */
	length = -EINVAL;
	if (*ppos != 0)
		goto out;

	length = -ENOMEM;
	data = vmalloc(count);
	if (!data)
		goto out;

	length = -EFAULT;
	if (copy_from_user(data, buf, count) != 0)
		goto out;

	length = security_load_policy(&selinux_state, data, count, &load_state);
	if (length) {
		pr_warn_ratelimited("SELinux: failed to load policy\n");
		goto out;
	}

	selinux_policy_commit(&selinux_state, &load_state);

	length = count;

	vfree(plm->data);
	plm->data = data;
	plm->len = length;
out:
	mutex_unlock(&selinux_state.policy_mutex);
	return length;
}

static int sel_release_policy(struct inode *inode, struct file *filp)
{
	struct policy_load_memory *plm = filp->private_data;

	BUG_ON(!plm);
	vfree(plm->data);
	kfree(plm);

	return 0;
}

static const struct file_operations sel_policy_ops = {
	.read		= sel_read_policy,
	.write		= sel_write_policy,
	.release	= sel_release_policy,
	.llseek		= generic_file_llseek,
};

static int selinux_policy_getfd(void)
{
	struct policy_load_memory *plm = NULL;
	int rc, fd;

	mutex_lock(&selinux_state.policy_mutex);

	rc = -ENOMEM;
	plm = kzalloc(sizeof(*plm), GFP_KERNEL);
	if (!plm)
		goto err;

	rc = security_read_policy(&selinux_state, &plm->data, &plm->len);
	if (rc)
		goto err;

	fd = anon_inode_getfd("[tsu_selinux_policy]", &sel_policy_ops,
			      plm, O_RDWR|O_CLOEXEC);
	if (fd < 0) {
		rc = fd;
		goto err;
	}

	mutex_unlock(&selinux_state.policy_mutex);
	
	return fd;
err:
	mutex_unlock(&selinux_state.policy_mutex);

	if (plm)
		vfree(plm->data);
	kfree(plm);
	return rc;
}


int handle_selinux_policy_getfd(unsigned long arg)
{
	int fd = selinux_policy_getfd();
	
	if (fd < 0)
		return fd;

	return copy_to_user((void __user *)arg, &fd, sizeof(int));
}
