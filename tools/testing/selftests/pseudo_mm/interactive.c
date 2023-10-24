#include <assert.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "pseudo_mm_ioctl.h"
#include "common.h"

#define DEVICE_PATH "/dev/pseudo_mm"
#define DAX_DEVICE_PATH "/dev/dax0.0"
#define IMAGE_FILE "one-page.img"
#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)

/*
 * By huang-jl: This test is mainly used for crash utility.
 * (More info https://github.com/crash-utility/crash)
 *
 * I use the live system mode of crash to detect whether the page has been
 * allocated on dax device or local memory in qemu.
 *
 * I use getchar() to pause the process for simplicity and that's also why I
 * called this test interactive :)
 */

int main()
{
	// 1. create a pseudo_mm
	// 2. add an one-page anon mapping to pseudo_mm
	// 3. fill the memory content of this one-page mapping with a image file
	int ret, fd, pseudo_mm_id, nr_pages = 278;
	const int seed = 0x123123;
	const unsigned long dax_pgoff = 777;
	const unsigned long start = 0xdeadaUL << PAGE_SHIFT;
	const unsigned long middle_pgoff = nr_pages / 2;
	const unsigned long vma1[2] = { start,
					start + middle_pgoff * PAGE_SIZE };
	// By huang-jl: we add 1 here to prevent vma merge
	// so that to make sure that there is two vmas.
	const unsigned long vma2[2] = { start + PAGE_SIZE * (middle_pgoff + 1),
					start + PAGE_SIZE * (nr_pages + 1) };
	unsigned long addr;
	pid_t pid;
	struct pseudo_mm_attach_param attach_param;

	fd = open(DEVICE_PATH, O_RDWR);
	assert(fd > 0);
	ret = ioctl(fd, PSEUDO_MM_IOC_CREATE, (void *)(&pseudo_mm_id));
	assert(ret == 0 && pseudo_mm_id > 0);

	ret = fill_dax_device(dax_pgoff, nr_pages, seed);
	assert(ret == 0);

	// attach this mapping to current process amd
	// check the memory content

	ret = add_mmap_to(fd, pseudo_mm_id, vma1[0], vma1[1],
			  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	assert(ret == 0);
	ret = add_mmap_to(fd, pseudo_mm_id, vma2[0], vma2[1],
			  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	assert(ret == 0);

	ret = setup_anon_map_pt(fd, pseudo_mm_id, vma1[0], vma1[1] - vma1[0],
				dax_pgoff);
	assert(ret == 0);
	printf("setup anon map from %#lx - %#lx\n", vma1[0], vma1[1]);
	ret = setup_anon_map_pt(fd, pseudo_mm_id, vma2[0], vma2[1] - vma2[0],
				dax_pgoff + middle_pgoff);
	assert(ret == 0);
	printf("setup anon map from %#lx - %#lx\n", vma2[0], vma2[1]);

	// first bring back half
	ret = bring_back_map(fd, pseudo_mm_id, vma1[0], vma1[1] - vma1[0]);
	assert(ret == 0);
	printf("bring back pseudo_mm of %#lx - %#lx\n", vma1[0], vma1[1]);

	pid = fork();
	assert(pid >= 0);
	if (pid == 0) {
		attach_param.id = pseudo_mm_id;
		attach_param.pid = getpid();
		ret = ioctl(fd, PSEUDO_MM_IOC_ATTACH, (void *)(&attach_param));
		assert(ret == 0);
		printf("attach succeed and start check anon page content");
		for (addr = vma1[0]; addr < vma1[1]; addr += PAGE_SIZE) {
			ret = check_page_content((void *)addr, seed);
			assert(ret == 0);
		}
		for (addr = vma2[0]; addr < vma2[1]; addr += PAGE_SIZE) {
			ret = check_page_content((void *)addr, seed);
			assert(ret == 0);
		}
		printf("child process %d press any key to continue\n",
		       getpid());
		getchar();
		exit(EXIT_SUCCESS);
	} else {
		int status;
		assert(waitpid(pid, &status, 0) == pid);
		assert(WIFEXITED(status));
		assert(WEXITSTATUS(status) == 0);
	}

	// then bring another half back
	ret = bring_back_map(fd, pseudo_mm_id, vma2[0], vma2[1] - vma2[0]);
	assert(ret == 0);
	printf("bring back pseudo_mm of %#lx - %#lx\n", vma2[0], vma2[1]);
	attach_param.id = pseudo_mm_id;
	attach_param.pid = getpid();
	ret = ioctl(fd, PSEUDO_MM_IOC_ATTACH, (void *)(&attach_param));
	assert(ret == 0);
	printf("attach succeed after bring back map\n");
	for (addr = vma1[0]; addr < vma1[1]; addr += PAGE_SIZE) {
		ret = check_page_content((void *)addr, seed);
		assert(ret == 0);
	}
	for (addr = vma2[0]; addr < vma2[1]; addr += PAGE_SIZE) {
		ret = check_page_content((void *)addr, seed);
		assert(ret == 0);
	}
	printf("check page content succeed after bringing back map!\n");
	printf("main process %d press any key to continue\n", getpid());
	getchar();

	printf("start write vma1 (%#lx - %#lx)\n", vma1[0], vma1[1]);
	for (addr = vma1[0]; addr < vma1[1]; addr += PAGE_SIZE)
		*(char *)(addr) = 'H';

	printf("main process %d press any key to continue\n", getpid());
	getchar();
	printf("start write vma2 (%#lx - %#lx)\n", vma2[0], vma2[1]);
	for (addr = vma2[0]; addr < vma2[1]; addr += PAGE_SIZE)
		*(char *)(addr) = 'H';
	printf("main process %d press any key to exit\n", getpid());
	getchar();
	close(fd);
	return 0;
}
