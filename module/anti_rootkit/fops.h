#ifndef _ANTI_ROOTKIT_FOPS
#define _ANTI_ROOTKIT_FOPS

#include <linux/fs.h>
#include "utils.h"

#define FOPS_OVERWRITE_READ (1 << 0)
#define FOPS_OVERWRITE_READ_ITER (1 << 1)
#define FOPS_OVERWRITE_WRITE (1 << 2)
#define FOPS_OVERWRITE_WRITE_ITER (1 << 3)
#define FOPS_OVERWRITE_ITERATE_SHARED (1 << 4)
#define FOPS_OVERWRITE_LLSEEK (1 << 5)
#define FOPS_OVERWRITE_FSYNC (1 << 6)

struct important_fops {
    struct fun_protector read;
    struct fun_protector read_iter;
    struct fun_protector write;
    struct fun_protector write_iter;
    struct fun_protector iterate_shared;
    struct fun_protector llseek;
    struct fun_protector fsync;
};

int fops_init(void);
void fops_check_all(void);

#endif
