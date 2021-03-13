#define LOG_LEVEL_DEBUG 4
#define LOG_LEVEL_INFO 3
#define LOG_LEVEL_WARN 2
#define LOG_LEVEL_ERR 1
#define LOG_LEVEL_NONE 0

#define LOG_LEVEL LOG_LEVEL_DEBUG
#define LOG_TAG "antirootkit"

#if LOG_LEVEL >= 4
#define log_debug(str, ...) printk(KERN_DEBUG LOG_TAG ": " str, ##__VA_ARGS__)
#else 
#define log_debug(str, ...)
#endif

#if LOG_LEVEL >= 3
#define log_info(str, ...) printk(KERN_INFO LOG_TAG ": " str, ##__VA_ARGS__)
#else 
#define log_info(str, ...)
#endif

#if LOG_LEVEL >= 2
#define log_warn(str, ...) printk(KERN_WARNING LOG_TAG ": " str, ##__VA_ARGS__)
#else 
#define log_warn(str, ...)
#endif

#if LOG_LEVEL >= 1
#define log_err(str, ...) printk(KERN_ERROR LOG_TAG ": " str, ##__VA_ARGS__)
#else 
#define log_err(str, ...)
#endif

#define DETECT_SYSCALL_TABLE 1
#define DETECT_MSR_LSTAR 1
#define DETECT_WP 1

#define RECOVER_SYSCALL_TABLE 1
#define RECOVER_MSR_LSTAR 1
#define RECOVER_WP 1
