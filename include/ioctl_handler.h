#ifndef __TSU_H_IOCTL_HANDLER
#define __TSU_H_IOCTL_HANDLER

int handle_transform(unsigned long arg);
int handle_selinux_policy_getfd(unsigned long arg);
int handle_cgroup_hack(unsigned long arg);

#endif
