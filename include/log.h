#ifndef __TSU_H_LOG
#define __TSU_H_LOG

#include <linux/printk.h>
#include <linux/stringify.h>

#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) "TerminalSU:" __FILE__ ":%s:" __stringify(__LINE__) ": " fmt, __func__
#endif

#endif
