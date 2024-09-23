#include <linux/fs.h>
#include <linux/module.h>

#include "log.h" // IWYU pragma: keep
#include "tsu.h"
#include "core.h"


static int __init terminalsu_init(void)
{
	tsu_core_init();
	return 0;
}

static void __exit terminalsu_exit(void)
{
	tsu_core_exit();
}

module_init(terminalsu_init);
module_exit(terminalsu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("mlatus");
MODULE_DESCRIPTION("Android TerminalSU");

MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
