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
#include "common.h"

#define DEVICE_PATH "/dev/pseudo_mm"
#define DAX_DEVICE_PATH "/dev/dax0.0"
#define IMAGE_FILE "one-page.img"
#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)

/*
 * @fd: the fd of pseudo_mm device
 */
int clean_all_pseudo_mm(int fd)
{
	int pseudo_mm_id = -1;
	return ioctl(fd, PSEUDO_MM_IOC_DELETE, (void *)(&pseudo_mm_id));
}

FIXTURE(single_page_bring_back)
{
	int pseudo_mm_id, fd;
	unsigned long seed;
};

FIXTURE_SETUP(single_page_bring_back)
{
	// 1. create a pseudo_mm
	// 2. add an one-page anon mapping to pseudo_mm
	// 3. fill the memory content of this one-page mapping with a image file
	int ret;

	TH_LOG("test start pid %d ppid %d", getpid(), getppid());

	self->seed = 0x123123;
	self->fd = open(DEVICE_PATH, O_RDWR);
	ASSERT_GT(self->fd, 0)
	{
		TH_LOG("open misc driver " DEVICE_PATH " failed: %d!",
		       self->fd);
	}

	ret = clean_all_pseudo_mm(self->fd);
	ASSERT_EQ(ret, 0);

	ret = ioctl(self->fd, PSEUDO_MM_IOC_CREATE,
		    (void *)(&self->pseudo_mm_id));
	ASSERT_TRUE(ret == 0 && self->pseudo_mm_id > 0);
	TH_LOG("process %d create pseudo_mm %d", getpid(), self->pseudo_mm_id);

	ret = fill_dax_device(192, 1, self->seed);
	ASSERT_EQ(ret, 0);
}

FIXTURE_TEARDOWN(single_page_bring_back)
{
	close(self->fd);
}

TEST_F(single_page_bring_back, simple)
{
	// attach this mapping to current process amd
	// check the memory content
	int ret;
	pid_t pid;
	const unsigned long start = 0xdead0UL << PAGE_SHIFT;
	const unsigned long end = start + PAGE_SIZE;
	struct pseudo_mm_attach_param attach_param;

	TH_LOG("try to add and fill anon map #%lx - #%lx", start, end);
	ret = add_mmap_to(self->fd, self->pseudo_mm_id, start, end,
			  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	ASSERT_EQ(ret, 0);
	ret = setup_anon_map_pt(self->fd, self->pseudo_mm_id, start, PAGE_SIZE,
				192);
	ASSERT_EQ(ret, 0);
	TH_LOG("add and fill anon map (#%lx - #%lx) finish", start, end);

	pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		attach_param.id = self->pseudo_mm_id;
		attach_param.pid = getpid();
		ret = ioctl(self->fd, PSEUDO_MM_IOC_ATTACH,
			    (void *)(&attach_param));
		ASSERT_EQ(ret, 0);
		TH_LOG("attach succeed and start check anon page content");
		ret = check_page_content((void *)start, self->seed);
		ASSERT_EQ(ret, 0);
		exit(EXIT_SUCCESS);
	} else {
		int status;
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		ASSERT_TRUE(WIFEXITED(status));
		ASSERT_EQ(WEXITSTATUS(status), 0);
	}

	ret = bring_back_map(self->fd, self->pseudo_mm_id, start, PAGE_SIZE);
	ASSERT_EQ(ret, 0);
	attach_param.id = self->pseudo_mm_id;
	attach_param.pid = getpid();
	ret = ioctl(self->fd, PSEUDO_MM_IOC_ATTACH, (void *)(&attach_param));
	ASSERT_EQ(ret, 0);
	TH_LOG("attach succeed after bring back map");
	ret = check_page_content((void *)start, self->seed);
	ASSERT_EQ(ret, 0);
	TH_LOG("check page content succeed after bringing back map!");
}

TEST_F(single_page_bring_back, bring_back_wo_setup_pt)
{
	int ret;
	const unsigned long start = 0xdead0UL << PAGE_SHIFT;
	const unsigned long end = start + PAGE_SIZE;

	TH_LOG("try to add and fill anon map #%lx - #%lx", start, end);
	ret = add_mmap_to(self->fd, self->pseudo_mm_id, start, end,
			  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	ASSERT_EQ(ret, 0);

	ret = bring_back_map(self->fd, self->pseudo_mm_id, start, PAGE_SIZE);
	ASSERT_NE(ret, 0);
}

TEST_F(single_page_bring_back, double_bring_back)
{
	int ret;
	const unsigned long start = 0xdead0UL << PAGE_SHIFT;
	const unsigned long end = start + PAGE_SIZE;
	struct pseudo_mm_attach_param attach_param;

	TH_LOG("try to add and fill anon map #%lx - #%lx", start, end);
	ret = add_mmap_to(self->fd, self->pseudo_mm_id, start, end,
			  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	ASSERT_EQ(ret, 0);
	ret = setup_anon_map_pt(self->fd, self->pseudo_mm_id, start, PAGE_SIZE,
				192);
	ASSERT_EQ(ret, 0);
	TH_LOG("add and fill anon map (#%lx - #%lx) finish", start, end);

	ret = bring_back_map(self->fd, self->pseudo_mm_id, start, PAGE_SIZE);
	ASSERT_EQ(ret, 0);
	attach_param.id = self->pseudo_mm_id;
	attach_param.pid = getpid();
	ret = ioctl(self->fd, PSEUDO_MM_IOC_ATTACH, (void *)(&attach_param));
	ASSERT_EQ(ret, 0);
	TH_LOG("attach succeed after bring back map");
	ret = check_page_content((void *)start, self->seed);
	ASSERT_EQ(ret, 0);
	TH_LOG("check page content succeed after bringing back map!");

	// here double bring back
	ret = bring_back_map(self->fd, self->pseudo_mm_id, start, PAGE_SIZE);
	ASSERT_NE(ret, 0);
}

TEST_F(single_page_bring_back, bring_back_and_write)
{
	int ret;
	pid_t pid;
	const unsigned long start = 0xdead0UL << PAGE_SHIFT;
	const unsigned long end = start + PAGE_SIZE;
	struct pseudo_mm_attach_param attach_param;

	TH_LOG("try to add and fill anon map #%lx - #%lx", start, end);
	ret = add_mmap_to(self->fd, self->pseudo_mm_id, start, end,
			  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	ASSERT_EQ(ret, 0);
	ret = setup_anon_map_pt(self->fd, self->pseudo_mm_id, start, PAGE_SIZE,
				192);
	ASSERT_EQ(ret, 0);
	TH_LOG("add and fill anon map (#%lx - #%lx) finish", start, end);
	ret = bring_back_map(self->fd, self->pseudo_mm_id, start, PAGE_SIZE);
	ASSERT_EQ(ret, 0);

	pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		char *iter;
		int i;
		attach_param.id = self->pseudo_mm_id;
		attach_param.pid = getpid();
		ret = ioctl(self->fd, PSEUDO_MM_IOC_ATTACH,
			    (void *)(&attach_param));
		ASSERT_EQ(ret, 0);
		TH_LOG("child attach pseudo_mm succeed");
		ret = check_page_content((void *)start, self->seed);
		ASSERT_EQ(ret, 0);
		TH_LOG("child check page content succeed");
		// start write some data into `start`
		for (i = 0; i < PAGE_SIZE; i++) {
			iter = (char *)(start + i);
			*iter = 'H';
		}
		TH_LOG("child write to attached area finish");
		exit(EXIT_SUCCESS);
	} else {
		int status;
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		ASSERT_TRUE(WIFEXITED(status));
		ASSERT_EQ(WEXITSTATUS(status), 0);
	}
	attach_param.id = self->pseudo_mm_id;
	attach_param.pid = getpid();
	ret = ioctl(self->fd, PSEUDO_MM_IOC_ATTACH, (void *)(&attach_param));
	ASSERT_EQ(ret, 0);
	TH_LOG("main attach pseudo_mm succeed");
	ret = check_page_content((void *)start, self->seed);
	ASSERT_EQ(ret, 0);
	TH_LOG("main check page content succeed after child write");
}

FIXTURE(multi_pages_bring_back)
{
	int pseudo_mm_id, fd;
	unsigned long seed, nr_pages, pgoff;
};

FIXTURE_SETUP(multi_pages_bring_back)
{
	// 1. create a pseudo_mm
	// 2. add an one-page anon mapping to pseudo_mm
	// 3. fill the memory content of this one-page mapping with a image file
	int ret;

	TH_LOG("test start pid %d ppid %d", getpid(), getppid());

	self->seed = 0x123125;
	self->nr_pages = 125;
	self->pgoff = 333;
	self->fd = open(DEVICE_PATH, O_RDWR);
	ASSERT_GT(self->fd, 0)
	{
		TH_LOG("open misc driver " DEVICE_PATH " failed: %d!",
		       self->fd);
	}

	ret = clean_all_pseudo_mm(self->fd);
	ASSERT_EQ(ret, 0);

	ret = ioctl(self->fd, PSEUDO_MM_IOC_CREATE,
		    (void *)(&self->pseudo_mm_id));
	ASSERT_TRUE(ret == 0 && self->pseudo_mm_id > 0);
	TH_LOG("process %d create pseudo_mm %d", getpid(), self->pseudo_mm_id);

	ret = fill_dax_device(self->pgoff, self->nr_pages, self->seed);
	ASSERT_EQ(ret, 0);
}

FIXTURE_TEARDOWN(multi_pages_bring_back)
{
	close(self->fd);
}

TEST_F(multi_pages_bring_back, simple)
{
	int ret, i;
	pid_t pid;
	const unsigned long start = 0xdeadaUL << PAGE_SHIFT;
	const unsigned long end = start + PAGE_SIZE * self->nr_pages;
	struct pseudo_mm_attach_param attach_param;

	TH_LOG("try to add and fill anon map #%lx - #%lx", start, end);
	ret = add_mmap_to(self->fd, self->pseudo_mm_id, start, end,
			  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	ASSERT_EQ(ret, 0);
	ret = setup_anon_map_pt(self->fd, self->pseudo_mm_id, start,
				PAGE_SIZE * self->nr_pages, self->pgoff);
	ASSERT_EQ(ret, 0);
	TH_LOG("add and fill anon map (#%lx - #%lx) finish", start, end);

	pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		attach_param.id = self->pseudo_mm_id;
		attach_param.pid = getpid();
		ret = ioctl(self->fd, PSEUDO_MM_IOC_ATTACH,
			    (void *)(&attach_param));
		ASSERT_EQ(ret, 0);
		TH_LOG("child attach pseudo_mm succeed");
		for (i = 0; i < self->nr_pages; i++) {
			ret = check_page_content(
				(void *)(start + i * PAGE_SIZE), self->seed);
			ASSERT_EQ(ret, 0);
		}
		TH_LOG("child check page content succeed");
		exit(EXIT_SUCCESS);
	} else {
		int status;
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		ASSERT_TRUE(WIFEXITED(status));
		ASSERT_EQ(WEXITSTATUS(status), 0);
	}

	ret = bring_back_map(self->fd, self->pseudo_mm_id, start,
			     PAGE_SIZE * self->nr_pages);
	ASSERT_EQ(ret, 0);
	attach_param.id = self->pseudo_mm_id;
	attach_param.pid = getpid();
	ret = ioctl(self->fd, PSEUDO_MM_IOC_ATTACH, (void *)(&attach_param));
	ASSERT_EQ(ret, 0);
	TH_LOG("main attach pseudo_mm succeed");
	for (i = 0; i < self->nr_pages; i++) {
		ret = check_page_content((void *)(start + i * PAGE_SIZE),
					 self->seed);
		ASSERT_EQ(ret, 0);
	}
	TH_LOG("main check page content succeed after child write");
}

TEST_F(multi_pages_bring_back, write)
{
	int ret, i;
	pid_t pid;
	const unsigned long start = 0xdeadaUL << PAGE_SHIFT;
	const unsigned long end = start + PAGE_SIZE * self->nr_pages;
	struct pseudo_mm_attach_param attach_param;

	TH_LOG("try to add and fill anon map #%lx - #%lx", start, end);
	ret = add_mmap_to(self->fd, self->pseudo_mm_id, start, end,
			  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	ASSERT_EQ(ret, 0);
	ret = setup_anon_map_pt(self->fd, self->pseudo_mm_id, start,
				PAGE_SIZE * self->nr_pages, self->pgoff);
	ASSERT_EQ(ret, 0);
	TH_LOG("add and fill anon map (#%lx - #%lx) finish", start, end);
	ret = bring_back_map(self->fd, self->pseudo_mm_id, start,
			     PAGE_SIZE * self->nr_pages);
	ASSERT_EQ(ret, 0);

	pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		char *iter;
		int i;
		attach_param.id = self->pseudo_mm_id;
		attach_param.pid = getpid();
		ret = ioctl(self->fd, PSEUDO_MM_IOC_ATTACH,
			    (void *)(&attach_param));
		ASSERT_EQ(ret, 0);
		TH_LOG("child attach pseudo_mm succeed");
		for (i = 0; i < self->nr_pages; i++) {
			ret = check_page_content(
				(void *)(start + i * PAGE_SIZE), self->seed);
			ASSERT_EQ(ret, 0);
		}
		TH_LOG("child check page content succeed");
		// start write some data into `start`
		for (i = 0; i < PAGE_SIZE * self->nr_pages; i++) {
			iter = (char *)(start + i);
			*iter = 'H';
		}
		TH_LOG("child write to attached area finish");
		exit(EXIT_SUCCESS);
	} else {
		int status;
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		ASSERT_TRUE(WIFEXITED(status));
		ASSERT_EQ(WEXITSTATUS(status), 0);
	}

	attach_param.id = self->pseudo_mm_id;
	attach_param.pid = getpid();
	ret = ioctl(self->fd, PSEUDO_MM_IOC_ATTACH, (void *)(&attach_param));
	ASSERT_EQ(ret, 0);
	TH_LOG("main attach pseudo_mm succeed");
	for (i = 0; i < self->nr_pages; i++) {
		ret = check_page_content((void *)(start + i * PAGE_SIZE),
					 self->seed);
		ASSERT_EQ(ret, 0);
	}
	TH_LOG("main check page content succeed after child write");
}

TEST_F(multi_pages_bring_back, multi_vmas_bring_too_much)
{
	int ret;
	const unsigned long start = 0xdeadaUL << PAGE_SHIFT;
	const unsigned long middle_pgoff = self->nr_pages / 2;
	const unsigned long vma1[2] = { start,
					start + middle_pgoff * PAGE_SIZE };
	// By huang-jl: we add 1 here to prevent vma merge
	// so that to make sure that there is two vmas.
	const unsigned long vma2[2] = { start + PAGE_SIZE * (middle_pgoff + 1),
					start + PAGE_SIZE *
							(self->nr_pages + 1) };

	TH_LOG("try to add and fill anon map #%lx - #%lx", vma1[0], vma1[1]);
	ret = add_mmap_to(self->fd, self->pseudo_mm_id, vma1[0], vma1[1],
			  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	ASSERT_EQ(ret, 0);
	TH_LOG("try to add and fill anon map #%lx - #%lx", vma2[0], vma2[1]);
	ret = add_mmap_to(self->fd, self->pseudo_mm_id, vma2[0], vma2[1],
			  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	ASSERT_EQ(ret, 0);
	ret = setup_anon_map_pt(self->fd, self->pseudo_mm_id, vma1[0],
				vma1[1] - vma1[0], self->pgoff);
	ASSERT_EQ(ret, 0);
	ret = setup_anon_map_pt(self->fd, self->pseudo_mm_id, vma2[0],
				vma2[1] - vma2[0], self->pgoff + middle_pgoff);
	ASSERT_EQ(ret, 0);

	ret = bring_back_map(self->fd, self->pseudo_mm_id, vma1[0], vma2[1]);
	ASSERT_NE(ret, 0);
}

TEST_F(multi_pages_bring_back, multi_vmas_bring_half)
{
	int ret;
	const unsigned long start = 0xdeadaUL << PAGE_SHIFT;
	const unsigned long middle_pgoff = self->nr_pages / 2;
	const unsigned long vma1[2] = { start,
					start + middle_pgoff * PAGE_SIZE };
	// By huang-jl: we add 1 here to prevent vma merge
	// so that to make sure that there is two vmas.
	const unsigned long vma2[2] = { start + PAGE_SIZE * (middle_pgoff + 1),
					start + PAGE_SIZE *
							(self->nr_pages + 1) };
	unsigned long addr;
	struct pseudo_mm_attach_param attach_param;

	TH_LOG("try to add and fill anon map #%lx - #%lx", vma1[0], vma1[1]);
	ret = add_mmap_to(self->fd, self->pseudo_mm_id, vma1[0], vma1[1],
			  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	ASSERT_EQ(ret, 0);
	TH_LOG("try to add and fill anon map #%lx - #%lx", vma2[0], vma2[1]);
	ret = add_mmap_to(self->fd, self->pseudo_mm_id, vma2[0], vma2[1],
			  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	ASSERT_EQ(ret, 0);
	ret = setup_anon_map_pt(self->fd, self->pseudo_mm_id, vma1[0],
				vma1[1] - vma1[0], self->pgoff);
	ASSERT_EQ(ret, 0);
	ret = setup_anon_map_pt(self->fd, self->pseudo_mm_id, vma2[0],
				vma2[1] - vma2[0], self->pgoff + middle_pgoff);
	ASSERT_EQ(ret, 0);

	ret = bring_back_map(self->fd, self->pseudo_mm_id, vma1[0],
			     vma1[1] - vma1[0]);
	ASSERT_EQ(ret, 0);

	attach_param.id = self->pseudo_mm_id;
	attach_param.pid = getpid();
	ret = ioctl(self->fd, PSEUDO_MM_IOC_ATTACH, (void *)(&attach_param));
	ASSERT_EQ(ret, 0);
	TH_LOG("main attach pseudo_mm succeed");
	for (addr = vma1[0]; addr < vma1[1]; addr += PAGE_SIZE) {
		ret = check_page_content((void *)addr, self->seed);
		ASSERT_EQ(ret, 0);
	}
	for (addr = vma2[0]; addr < vma2[1]; addr += PAGE_SIZE) {
		ret = check_page_content((void *)addr, self->seed);
		ASSERT_EQ(ret, 0);
	}
	TH_LOG("main check page content succeed after child write");
}

TEST_F(multi_pages_bring_back, multi_vmas_bring_all)
{
	int ret;
	const unsigned long start = 0xdeadaUL << PAGE_SHIFT;
	const unsigned long middle_pgoff = self->nr_pages / 2;
	const unsigned long vma1[2] = { start,
					start + middle_pgoff * PAGE_SIZE };
	// By huang-jl: we add 1 here to prevent vma merge
	// so that to make sure that there is two vmas.
	const unsigned long vma2[2] = { start + PAGE_SIZE * (middle_pgoff + 1),
					start + PAGE_SIZE *
							(self->nr_pages + 1) };
	unsigned long addr;
	struct pseudo_mm_attach_param attach_param;

	TH_LOG("try to add and fill anon map #%lx - #%lx", vma1[0], vma1[1]);
	ret = add_mmap_to(self->fd, self->pseudo_mm_id, vma1[0], vma1[1],
			  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	ASSERT_EQ(ret, 0);
	TH_LOG("try to add and fill anon map #%lx - #%lx", vma2[0], vma2[1]);
	ret = add_mmap_to(self->fd, self->pseudo_mm_id, vma2[0], vma2[1],
			  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	ASSERT_EQ(ret, 0);
	ret = setup_anon_map_pt(self->fd, self->pseudo_mm_id, vma1[0],
				vma1[1] - vma1[0], self->pgoff);
	ASSERT_EQ(ret, 0);
	ret = setup_anon_map_pt(self->fd, self->pseudo_mm_id, vma2[0],
				vma2[1] - vma2[0], self->pgoff + middle_pgoff);
	ASSERT_EQ(ret, 0);

	ret = bring_back_map(self->fd, self->pseudo_mm_id, vma1[0],
			     vma1[1] - vma1[0]);
	ASSERT_EQ(ret, 0);
	ret = bring_back_map(self->fd, self->pseudo_mm_id, vma2[0],
			     vma2[1] - vma2[0]);
	ASSERT_EQ(ret, 0);

	attach_param.id = self->pseudo_mm_id;
	attach_param.pid = getpid();
	ret = ioctl(self->fd, PSEUDO_MM_IOC_ATTACH, (void *)(&attach_param));
	ASSERT_EQ(ret, 0);
	TH_LOG("main attach pseudo_mm succeed");
	for (addr = vma1[0]; addr < vma1[1]; addr += PAGE_SIZE) {
		ret = check_page_content((void *)addr, self->seed);
		ASSERT_EQ(ret, 0);
	}
	for (addr = vma2[0]; addr < vma2[1]; addr += PAGE_SIZE) {
		ret = check_page_content((void *)addr, self->seed);
		ASSERT_EQ(ret, 0);
	}
	TH_LOG("main check page content succeed after child write");
}

TEST_HARNESS_MAIN
