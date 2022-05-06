#ifndef __TAPDEV_H
#define __TAPDEV_H

int tapdev_init(const char *name);
int tapdev_send(void);
int tapdev_read(void);
int tapdev_test(void);

#define TAP_MIN_LEN 14
#define TAPDEV_NAME "tap0"

#endif
