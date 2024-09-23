#ifndef __TSU_H_TSU
#define __TSU_H_TSU

#include <linux/types.h>

#define TERMINAL_SU_OPTION 0xDEC0DE17

#define CMD_GETFD 0

struct tsu_string {
	size_t len;
	char *ptr;
};

struct tsu_cgrp_hack_param {
	int cgrp_fd;
	int cgrp_bpf_attach_type;
};

#define TSU_IOCTL_TYPE 0x47
#define TSU_IOCTL_TRANSFORM _IOW(TSU_IOCTL_TYPE, 0, struct tsu_string)
#define TSU_IOCTL_SEPOL_GETFD _IOR(TSU_IOCTL_TYPE, 1, int)
#define TSU_IOCTL_CGROUP_HACK _IOW(TSU_IOCTL_TYPE, 2, struct tsu_cgrp_hack_param)

#endif
