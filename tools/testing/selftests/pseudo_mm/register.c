#include <assert.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "../kselftest_harness.h"
#include "pseudo_mm_ioctl.h"

#define DEVICE_PATH "/dev/pseudo_mm"
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)

TEST(pseudo_mm_register)
{
	int fd, dax_fd, ret;
	fd = open(DEVICE_PATH, O_RDWR);
	ASSERT_GT(fd, 0);
	dax_fd = open("/dev/dax0.0", O_RDWR);
	ASSERT_GT(dax_fd, 0);
	ret = ioctl(fd, PSEUDO_MM_IOC_REGISTER, (void *)(&dax_fd));
	ASSERT_EQ(ret, 0);

	close(dax_fd);
	close(fd);
}

TEST_HARNESS_MAIN
