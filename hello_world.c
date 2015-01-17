#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros

/*
* Write a Linux kernel module, and stand-alone Makefile, that when loaded
* prints to the kernel debug log level, "Hello World!" Be sure to make
* the module unloadable as well.
*/

MODULE_LICENSE("GPL");
MODULE_AUTHOR("sotek <sotek72@gmail.com>");
MODULE_DESCRIPTION("A Simple Hello World module");



static int __init hello_init(void)
{
	//list_del_init(&__this_module.list);
	//kobject_del(&THIS_MODULE->mkobj.kobj);
    printk(KERN_INFO "Hello world!\n");
    return 0;    // Non-zero return means that the module couldn't be loaded.
}

static void __exit hello_cleanup(void)
{
    printk(KERN_INFO "Cleaning up module.\n");
}

module_init(hello_init);
module_exit(hello_cleanup);



