#include <linux/types.h>

#include "config.h"
#include "utils.h"
#include "important_functions.h"

static struct fun_prot {
    struct fun_protector tcp4_seq_show;
    struct fun_protector udp4_seq_show;
    struct fun_protector ip_rcv;
} important_protectors;

void important_functions_init(void)
{
    fprot_safe_cpy(&important_protectors.tcp4_seq_show,
                   (void *)lookup_name("tcp4_seq_show"));
    fprot_safe_cpy(&important_protectors.udp4_seq_show,
                   (void *)lookup_name("udp4_seq_show"));
    fprot_safe_cpy(&important_protectors.ip_rcv, (void *)lookup_name("ip_rcv"));
}

static void important_functions_recover(void)
{
    wp_disable();

    fprot_recover(&important_protectors.tcp4_seq_show);
    fprot_recover(&important_protectors.udp4_seq_show);
    fprot_recover(&important_protectors.ip_rcv);

    wp_enable();
}

void important_functions_check(void)
{
    if (fprot_validate(&important_protectors.tcp4_seq_show))
        pr_warn("'tcp4_seq_show' has been hooked");
    if (fprot_validate(&important_protectors.udp4_seq_show))
        pr_warn("'udp4_seq_show' has been hooked");
    if (fprot_validate(&important_protectors.ip_rcv))
        pr_warn("'ip_rcv' has been hooked");

#if RECOVER_IMPORTANT_FUNCTIONS
    important_functions_recover();
#endif /* RECOVER_IMPORTANT_FUNCTIONS */
}
