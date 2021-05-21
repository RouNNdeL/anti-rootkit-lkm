#ifndef _ANTI_ROOTKIT_CONFIG
#define _ANTI_ROOTKIT_CONFIG

#undef pr_fmt
#define pr_fmt(fmt) "antirootkit: " fmt

#define DETECT_SYSCALL_TABLE 1
#define DETECT_MSR_LSTAR 1
#define DETECT_PINNED_BITS 1
#define DETECT_MODULE_LIST 1
#define DETECT_FOPS 1
#define DETECT_IDT 1
#define DETECT_IMPORTANT_FUNCTIONS 1

#define RECOVER_SYSCALL_TABLE 0
#define RECOVER_MSR_LSTAR 1
#define RECOVER_PINNED_BITS 1
#define RECOVER_MODULE_LIST 1
#define RECOVER_FOPS 1
#define RECOVER_IDT 1
#define RECOVER_IMPORTANT_FUNCTIONS 1

/* Use with caution, can cause system instability */
#define UNLOAD_SUSPECT_MODULE 0

/* In seconds */
#define CHECK_INTERVAL 60

#endif
