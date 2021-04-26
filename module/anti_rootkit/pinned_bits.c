#include "pinned_bits.h"
#include "utils.h"

static unsigned long cr4_pinned_bits;

static inline bool wp_set(void)
{
    return (read_cr0() & X86_CR0_WP) > 0;
}

void pinned_bits_init(void)
{
    unsigned long cr4 = native_read_cr4();
    cr4_pinned_bits = cr4 & (X86_CR4_SMEP | X86_CR4_SMAP | X86_CR4_UMIP | X86_CR4_FSGSBASE);}

static inline void check_cr0(void)
{
    if (unlikely(!wp_set())) {
        pr_warn("cr0 WP bit cleared");
#if RECOVER_PINNED_BITS
        pr_info("recovering cr0 WP bit");
        wp_enable();
#endif /* RECOVER_PINNED_BITS */
    }
}

static inline void check_cr4(void)
{
    unsigned long cr4 = native_read_cr4();
    if (unlikely((cr4 & cr4_pinned_bits) != cr4_pinned_bits)) {
        pr_warn("cr4 pinned bits changed: 0x%lx", (cr4 & cr4_pinned_bits));
#if RECOVER_PINNED_BITS
        pr_info("recovering cr4 bits");
        _write_cr4(cr4 | cr4_pinned_bits);
#endif /* RECOVER_PINNED_BITS */
    }
}

void pinned_bits_check(void)
{
    check_cr0();
    check_cr4();
}
