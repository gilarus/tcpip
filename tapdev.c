#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <time.h>
#include <stdlib.h>

#include <errno.h>

#include "tapdev.h"

#include "tcpip.h"

#define CLONEDEV "/dev/net/tun"

static int fd;

int tapdev_init(const char *name)
{
	struct ifreq ifr;
	int err, len;

	fd = open(CLONEDEV, O_RDWR);
	if (fd == -1) {
		perror("tap init ");
		exit(1);
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP|IFF_NO_PI;
	if (name == NULL)
		strcpy(ifr.ifr_name, TAPDEV_NAME);
	else
		strncpy(ifr.ifr_name, name, strlen(name) % IFNAMSIZ);

	err = ioctl(fd, TUNSETIFF, (void *)&ifr);
	if (err == -1) {
		perror("tap ioctl ");
		close(fd);
		exit(1);
	}
	return err;
}

int tapdev_send(void)
{
	int ret;

	if (tcpip_len < TAP_MIN_LEN)
		return 0;

	ret = write(fd, tcpip_buf, tcpip_len);
	if (ret == -1){
		perror("tap write ");
		exit(1);
	}
	return ret;
}

int tapdev_read(void)
{
	struct timeval tv;
	fd_set fdset;
	int ret;

	tv.tv_sec = 0;
	tv.tv_usec = 1000;

	FD_ZERO(&fdset);
	FD_SET(fd, &fdset);

	ret = select(fd + 1, &fdset, NULL, NULL, &tv);
	if (ret == 0)
		return 0;

	ret = read(fd, tcpip_buf, ETH_BUF_MAX);
	if (ret == -1) {
		perror("tap read ");
		exit(1);
	}
	return ret;
}

int tapdev_test(void)
{
	return 0;
}
