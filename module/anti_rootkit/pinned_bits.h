#ifndef _ANTI_ROOTKIT_PINNED_BITS
#define _ANTI_ROOTKIT_PINNED_BITS

#include "asm/special_insns.h"
#include "linux/compiler.h"
#include <asm/processor-flags.h>
#include <linux/types.h>
#include "utils.h"
#include "config.h"

void pinned_bits_init(void);

void pinned_bits_check(void);

#endif
