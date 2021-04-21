#include <linux/types.h>

#include "config.h"
#include "utils.h"
#include "network.h"

static struct net_prot {
    struct fun_protector tcp4_seq_show;
    struct fun_protector udp4_seq_show;
    struct fun_protector ip_rcv;
} net_protectors;

void network_init(void)
{
    fprot_safe_cpy(&net_protectors.tcp4_seq_show,
                   (void *)lookup_name("tcp4_seq_show"));
    fprot_safe_cpy(&net_protectors.udp4_seq_show,
                   (void *)lookup_name("udp4_seq_show"));
    fprot_safe_cpy(&net_protectors.ip_rcv,
                   (void *)lookup_name("ip_rcv"));
}

static void network_recover(void) {
    wp_disable();
    fprot_recover(&net_protectors.tcp4_seq_show);
    fprot_recover(&net_protectors.udp4_seq_show);
    fprot_recover(&net_protectors.ip_rcv);
    wp_enable();
}

void network_check(void)
{
    if(!fprot_validate(&net_protectors.tcp4_seq_show))
        pr_warn("'tcp4_seq_show' has been hooked");
    if(!fprot_validate(&net_protectors.udp4_seq_show))
        pr_warn("'udp4_seq_show' has been hooked");
    if(!fprot_validate(&net_protectors.ip_rcv))
        pr_warn("'ip_rcv' has been hooked");

#if RECOVER_NETWORK
    network_recover();
#endif /* RECOVER_NETWORK */
}
