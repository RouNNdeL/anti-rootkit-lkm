#include "syscall_handler.h"
#include "config.h"

static void *syscall_handler;

bool syscall_handler_changed(void)
{
    return get_syscall_64_handler() != syscall_handler;
}

void syscall_handler_recover(void)
{
    set_syscall_64_handler(syscall_handler);
}

void syscall_handler_check(void)
{
    if (syscall_handler_changed()) {
        pr_warn("syscall entry address changed");
#if RECOVER_MSR_LSTAR
        pr_info("recovering syscall entry address");
        syscall_handler_recover();
#endif /* RECOVER_MSR_LSTAR */
    }
}

void syscall_handler_init(void) {
    syscall_handler = get_syscall_64_handler();
    pr_info("syscall handler is @ %px", syscall_handler);
}
