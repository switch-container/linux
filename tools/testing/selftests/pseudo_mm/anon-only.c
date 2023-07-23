#include <assert.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include "pseudo_mm_ioctl.h"

#define DEVICE_PATH "/dev/pseudo_mm"
#define IMAGE_FILE "one-page.img"
#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)

int main(void)
{
	int fd, pseudo_mm_id, ret, img_fd, i;
	pid_t pid;
	char ch;
	char *iter;
	struct pseudo_mm_add_anon_param add_anon_param;
	struct pseudo_mm_fill_anon_param fill_anon_param;
	struct pseudo_mm_attach_param attach_param;
	unsigned long start, end;

	fd = open(DEVICE_PATH, O_RDWR);
	assert(fd > 0);

	ret = ioctl(fd, PSEUDO_MM_IOC_CREATE, (void*) (&pseudo_mm_id));
	assert(ret == 0 && pseudo_mm_id > 0);

	// user space allowed address is <= 0x7fff_ffff_ffff
	start = 0xdead0UL << PAGE_SHIFT;
	end = 0xdead1UL << PAGE_SHIFT;

	add_anon_param.id = pseudo_mm_id;
	add_anon_param.start = start;
	add_anon_param.end = end;
	add_anon_param.prot = PROT_READ | PROT_WRITE;
	add_anon_param.flags = MAP_ANONYMOUS | MAP_PRIVATE;
	ret = ioctl(fd, PSEUDO_MM_IOC_ADD_ANON, (void *) (&add_anon_param));
	assert(ret == 0);

	fill_anon_param.id = pseudo_mm_id;
	fill_anon_param.start = start;
	fill_anon_param.end = end;

	img_fd = open(IMAGE_FILE, O_RDWR);
	assert(img_fd > 0);
	for (i = 0; i < PAGE_SIZE; i++) {
		ch = (i % 10) + 0x50;
		ret = pwrite(img_fd, (void *)(&ch), 1, i);
		assert(ret == 1);
	}
	fsync(img_fd);

	fill_anon_param.fd = img_fd;

	ret = ioctl(fd, PSEUDO_MM_IOC_FILL_ANON, (void *) (&fill_anon_param));
	assert(ret == 0);

	pid = getpid();
	attach_param.id = pseudo_mm_id;
	attach_param.pid = pid;
	ret = ioctl(fd, PSEUDO_MM_IOC_ATTACH, (void *) (&attach_param));
	assert(ret == 0);

	for(i = 0; i < PAGE_SIZE; i++) {
		iter = (char *)(start + i);
		assert(*iter == ((i % 10) + 0x50));
	}
	
	close(fd);
	ret = ioctl(fd, PSEUDO_MM_IOC_DELETE, (void *)(&pseudo_mm_id));
	assert(ret == 0);
	return 0;
}
