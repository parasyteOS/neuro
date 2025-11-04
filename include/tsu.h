#ifndef __TSU_H_TSU
#define __TSU_H_TSU

#include <linux/types.h>

#define TERMINAL_SU_OPTION 0xDEC0DE17

#define CMD_SEPOL_GETFD 0
#define CMD_TRANSFORM 1

struct tsu_string {
	size_t len;
	char *ptr;
};

#endif
