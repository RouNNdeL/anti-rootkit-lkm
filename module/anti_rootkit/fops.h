#ifndef _ANTI_ROOTKIT_FOPS
#define _ANTI_ROOTKIT_FOPS

#include <linux/fs.h>

#define FOPS_OVERWRITE_READ (1 << 0)
#define FOPS_OVERWRITE_WRITE (1 << 1)
#define FOPS_OVERWRITE_OPEN (1 << 2)
#define FOPS_OVERWRITE_ITERATE (1 << 3)
#define FOPS_WATCH_SIZE 16

struct important_fops {
    uint8_t read[FOPS_WATCH_SIZE];
    uint8_t write[FOPS_WATCH_SIZE];
    uint8_t open[FOPS_WATCH_SIZE];
    uint8_t iterate[FOPS_WATCH_SIZE];
};

int fops_init(void);
void fops_check_all(void);

#endif
