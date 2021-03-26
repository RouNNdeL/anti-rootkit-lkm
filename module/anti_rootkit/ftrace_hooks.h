#ifndef _ANTI_ROOTKIT_FTRACE_HOOKS
#define _ANTI_ROOTKIT_FTRACE_HOOKS

#include <linux/version.h>
#include <linux/ftrace.h>


#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
struct ftrace_regs {
    struct pt_regs regs;
};
#endif

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0))
#define PTREGS_SYSCALL_STUBS 1
#endif

#define HOOK(_name, _function, _original)                                      \
    {                                                                          \
        .name = _name, .function = (_function), .original = (_original),       \
    }
/*
 * ftrace hooking from https://github.com/ilammy/ftrace-hook
 */

/*
 * There are two ways of preventing vicious recursive loops when hooking:
 * - detect recusion using function return address (USE_FENTRY_OFFSET = 0)
 * - avoid recusion by jumping over the ftrace call (USE_FENTRY_OFFSET = 1)
 */
#define USE_FENTRY_OFFSET 0

/**
 * struct ftrace_hook - describes a single hook to install
 *
 * @name:     name of the function to hook
 *
 * @function: pointer to the function to execute instead
 *
 * @original: pointer to the location where to save a pointer
 *            to the original function
 *
 * @address:  kernel address of the function entry
 *
 * @ops:      ftrace_ops state for this function hook
 *
 * The user should fill in only &name, &hook, &orig fields.
 * Other fields are considered implementation details.
 */
struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};

int fh_install_hook(struct ftrace_hook *hook);
int fh_install_hooks(struct ftrace_hook *hooks, size_t count);
void fh_remove_hook(struct ftrace_hook *hook);
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count);

#endif
