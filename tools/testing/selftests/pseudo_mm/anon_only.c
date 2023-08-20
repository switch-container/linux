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

TEST(pseudo_mm_create)
{
	int i, j, fd, ret;
	int *pseudo_mm_ids;
	const int size = 128;

	SKIP(return, "skip create test");

	fd = open(DEVICE_PATH, O_RDWR);
	ASSERT_GT(fd, 0)
	{
		TH_LOG("open misc driver " DEVICE_PATH " failed: %d!", fd);
	}
	pseudo_mm_ids = calloc(size, sizeof(int));
	ASSERT_NE(pseudo_mm_ids, NULL)
	{
		TH_LOG("allocate array of pseudo_mm_id failed!");
	}
	for (i = 0; i < size; i++) {
		ret = ioctl(fd, PSEUDO_MM_IOC_CREATE,
			    (void *)(&pseudo_mm_ids[i]));
		EXPECT_TRUE(ret == 0 && pseudo_mm_ids[i] > 0);
		// check for pseudo_mm_id duplication
		for (j = 0; j < i; j++)
			EXPECT_NE(pseudo_mm_ids[j], pseudo_mm_ids[i]);
	}

	for (i = 0; i < size; i++) {
		ret = ioctl(fd, PSEUDO_MM_IOC_DELETE,
			    (void *)(&pseudo_mm_ids[i]));
		EXPECT_EQ(ret, 0);
	}

	free(pseudo_mm_ids);
	close(fd);
}

FIXTURE(single_page_anon)
{
	int pseudo_mm_id, fd;
	unsigned long seed;
};

FIXTURE_SETUP(single_page_anon)
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

FIXTURE_TEARDOWN(single_page_anon)
{
	close(self->fd);
}

TEST_F(single_page_anon, simple_attach)
{
	// attach this mapping to current process amd
	// check the memory content
	int ret;
	pid_t pid;
	const unsigned long start = 0xdead0UL << PAGE_SHIFT;
	const unsigned long end = start + PAGE_SIZE;
	struct pseudo_mm_attach_param attach_param;

	pid = getpid();

	TH_LOG("try to add and fill anon map #%lx - #%lx", start, end);
	ret = add_mmap_to(self->fd, self->pseudo_mm_id, start, end,
			  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	ASSERT_EQ(ret, 0);
	ret = setup_anon_map_pt(self->fd, self->pseudo_mm_id, start, PAGE_SIZE,
				192);
	ASSERT_EQ(ret, 0);
	TH_LOG("add and fill anon map (#%lx - #%lx) finish", start, end);

	attach_param.id = self->pseudo_mm_id;
	attach_param.pid = pid;
	ret = ioctl(self->fd, PSEUDO_MM_IOC_ATTACH, (void *)(&attach_param));
	ASSERT_EQ(ret, 0);

	TH_LOG("attach succeed and start check anon page content");
	ret = check_page_content((void *)start, self->seed);
	ASSERT_EQ(ret, 0);

	TH_LOG("succeed to attach pseudo_mm to current process and check its content.");
}

TEST_F(single_page_anon, attach_to_conflict_addr)
{
	int ret;
	pid_t pid;
	void *addr;
	unsigned long start;
	unsigned long end;
	struct pseudo_mm_attach_param attach_param;
	// SKIP(return, "");

	pid = getpid();

	addr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	ASSERT_NE(addr, MAP_FAILED)
	{
		TH_LOG("mmap failed!");
	}

	start = (unsigned long)addr;
	end = start + PAGE_SIZE;
	TH_LOG("try to add and fill anon map #%lx - #%lx", start, end);
	ret = add_mmap_to(self->fd, self->pseudo_mm_id, start, end,
			  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	ASSERT_EQ(ret, 0);
	ret = setup_anon_map_pt(self->fd, self->pseudo_mm_id, start, PAGE_SIZE,
				0);
	ASSERT_EQ(ret, 0);

	attach_param.id = self->pseudo_mm_id;
	attach_param.pid = pid;
	ret = ioctl(self->fd, PSEUDO_MM_IOC_ATTACH, (void *)(&attach_param));
	ASSERT_NE(ret, 0)
	{
		TH_LOG("attach anon mapping to current process with conflict address succeed");
	}
}

/*
 * This test wants to make sure:
 * 1. one process create a pseudo_mm and exit
 * 2. another process can still attach this pseudo_mm
 *
 * So that the lifetime of pseudo_mm is not bind with process.
 */
FIXTURE(pseudo_mm_lifetime_simple)
{
	int fd;
	unsigned long start, end;
	unsigned long seed;
};

FIXTURE_SETUP(pseudo_mm_lifetime_simple)
{
	int ret;
	TH_LOG("test start pid %d ppid %d", getpid(), getppid());
	self->seed = 0x321321;
	self->start = 0xdead0UL << PAGE_SHIFT;
	self->end = 0xdead1UL << PAGE_SHIFT;
	self->fd = open(DEVICE_PATH, O_RDWR);
	ASSERT_GT(self->fd, 0);
	ASSERT_EQ(clean_all_pseudo_mm(self->fd), 0);

	ret = fill_dax_device(1, 1, self->seed);
	ASSERT_EQ(ret, 0);
}

FIXTURE_TEARDOWN(pseudo_mm_lifetime_simple)
{
	close(self->fd);
}

FIXTURE_VARIANT(pseudo_mm_lifetime_simple)
{
	unsigned long flags;
	unsigned long seed;
};

FIXTURE_VARIANT_ADD(pseudo_mm_lifetime_simple, private){
	.flags = MAP_ANONYMOUS | MAP_PRIVATE,
};

// FIXTURE_VARIANT_ADD(pseudo_mm_lifetime_simple, shared){
// 	.flags = MAP_ANONYMOUS | MAP_SHARED,
// };

TEST_F(pseudo_mm_lifetime_simple, XXX)
{
	pid_t pid;
	struct pseudo_mm_attach_param attach_param;
	int ret, pseudo_mm_id, pipe_fd[2];
	// SKIP(return, "");

	/*
	 * one process create, fill pseudo_mm then exit
	 */
	ASSERT_EQ(pipe(pipe_fd), 0);
	pid = fork();
	if (pid == 0) {
		close(pipe_fd[0]);
		ret = ioctl(self->fd, PSEUDO_MM_IOC_CREATE,
			    (void *)(&pseudo_mm_id));
		TH_LOG("process %d create pseudo_mm %d", getpid(),
		       pseudo_mm_id);
		ASSERT_EQ(ret, 0);
		ASSERT_GE(pseudo_mm_id, 1);

		ret = add_mmap_to(self->fd, pseudo_mm_id, self->start,
				  self->end, MAP_ANONYMOUS | MAP_PRIVATE, -1,
				  0);
		ASSERT_EQ(ret, 0);
		ret = setup_anon_map_pt(self->fd, pseudo_mm_id, self->start,
					PAGE_SIZE, 1);
		ASSERT_EQ(ret, 0);
		ASSERT_EQ(write(pipe_fd[1], &pseudo_mm_id,
				sizeof(pseudo_mm_id)),
			  sizeof(pseudo_mm_id));
		close(pipe_fd[1]);
		exit(EXIT_SUCCESS);
	} else {
		int status;
		close(pipe_fd[1]);
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		ASSERT_TRUE(WIFEXITED(status));
		ASSERT_EQ(WEXITSTATUS(status), 0);
	}
	TH_LOG("process %d wait for child %d to exit", getpid(), pid);
	ASSERT_EQ(read(pipe_fd[0], &pseudo_mm_id, sizeof(pseudo_mm_id)),
		  sizeof(pseudo_mm_id));
	close(pipe_fd[0]);

	// the creator of pseudo_mm has been terminated
	pid = getpid();
	attach_param.id = pseudo_mm_id;
	attach_param.pid = pid;
	ret = ioctl(self->fd, PSEUDO_MM_IOC_ATTACH, (void *)(&attach_param));
	ASSERT_EQ(ret, 0)
	{
		TH_LOG("pid %d pseudo_mm_id %d", pid, pseudo_mm_id);
	}

	ret = check_page_content((void *)self->start, self->seed);
	ASSERT_EQ(ret, 0);
}

/*
 * This test will test both private and shared anonymous memory:
 * 1. create a pseudo_mm.
 * 2. two process (named P1 and P2) will both attach to it.
 * 3. P1 try to modify the content in pseudo_mm's virtual address.
 * 4. P2 should not P1's modification.
 */
FIXTURE(single_page_anon_multi_attach)
{
	int fd, pseudo_mm_id;
	unsigned long start, end;
	unsigned long seed;
};

FIXTURE_VARIANT(single_page_anon_multi_attach)
{
	unsigned long flags;
};

FIXTURE_VARIANT_ADD(single_page_anon_multi_attach, private){
	.flags = MAP_ANONYMOUS | MAP_PRIVATE,
};

// FIXTURE_VARIANT_ADD(single_page_anon_multi_attach, shared){
// 	.flags = MAP_ANONYMOUS | MAP_SHARED,
// };

FIXTURE_SETUP(single_page_anon_multi_attach)
{
	int ret;
	TH_LOG("test start pid %d ppid %d", getpid(), getppid());
	self->seed = 0x456456;
	self->start = 0xdead0UL << PAGE_SHIFT;
	self->end = 0xdead1UL << PAGE_SHIFT;

	self->fd = open(DEVICE_PATH, O_RDWR);
	ASSERT_GT(self->fd, 0);
	ASSERT_EQ(clean_all_pseudo_mm(self->fd), 0);
	ret = ioctl(self->fd, PSEUDO_MM_IOC_CREATE,
		    (void *)(&self->pseudo_mm_id));
	ASSERT_TRUE(ret == 0 && self->pseudo_mm_id > 0);
	TH_LOG("process %d create pseudo_mm %d", getpid(), self->pseudo_mm_id);
	ret = fill_dax_device(2, 1, self->seed);
	ASSERT_EQ(ret, 0);

	ret = add_mmap_to(self->fd, self->pseudo_mm_id, self->start, self->end,
			  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	ASSERT_EQ(ret, 0);
	ret = setup_anon_map_pt(self->fd, self->pseudo_mm_id, self->start,
				PAGE_SIZE, 2);
	ASSERT_EQ(ret, 0);
}

FIXTURE_TEARDOWN(single_page_anon_multi_attach)
{
	close(self->fd);
}

/*
 * 1. two processes A and B both do pseudo_mm_attach to itself.
 * 2. A modify memory content in pseudo_mm area
 * 3. B should not notice those modifications made by A.
 *
 * No matter MAP_SHARED or MAP_PRIVATE for anonymous mapping.
 */
TEST_F(single_page_anon_multi_attach, one_writer_one_reader)
{
	// ctp means child(w)-to-parent(r) pipe
	// ptc means parent(r)-to-child(w) pipe
	int ret, i, ctp[2], ptc[2];
	char buf, *iter;
	pid_t pid, curr_pid;
	struct pseudo_mm_attach_param attach_param;
	// SKIP(return, "");

	ASSERT_EQ(pipe(ctp), 0);
	ASSERT_EQ(pipe(ptc), 0);
	pid = fork();
	ASSERT_GE(pid, 0);
	curr_pid = getpid();
	// both child and parent need attach
	attach_param.id = self->pseudo_mm_id;
	attach_param.pid = curr_pid;
	ret = ioctl(self->fd, PSEUDO_MM_IOC_ATTACH, (void *)(&attach_param));
	ASSERT_EQ(ret, 0)
	{
		TH_LOG("attach anon mapping to current process (%d) failed: %d!",
		       curr_pid, errno);
	}

	ret = check_page_content((void *)self->start, self->seed);
	ASSERT_EQ(ret, 0);

	if (pid == 0) {
		// child should not notice modification
		close(ptc[1]);
		close(ctp[0]);
		ASSERT_EQ(write(ctp[1], &buf, 1),
			  1); // notify parent to start modification
		close(ctp[1]);
		ASSERT_EQ(read(ptc[0], &buf, 1),
			  1); // wait for parent's modification
		close(ptc[0]);
		// make sure child does not see parent's modification
		ret = check_page_content((void *)self->start, self->seed);
		if (ret)
			exit(EXIT_FAILURE);
		exit(EXIT_SUCCESS);
	} else {
		int status;
		close(ptc[0]);
		close(ctp[1]);
		// parent modify memory content
		ASSERT_EQ(read(ctp[0], &buf, 1),
			  1); // wait for child's preparation
		close(ctp[0]);
		for (i = 0; i < PAGE_SIZE; i++) {
			iter = (char *)(self->start + i);
			*iter = 'X';
		}
		ASSERT_EQ(write(ptc[1], &buf, 1), 1);
		close(ptc[1]);
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		ASSERT_TRUE(WIFEXITED(status));
		ASSERT_EQ(WEXITSTATUS(status), 0);
	}
}

FIXTURE(multi_page)
{
	int fd, pseudo_mm_id;
	unsigned long start, end;
	int page_num;
	unsigned long seed;
};

FIXTURE_SETUP(multi_page)
{
	int fd, ret;

	self->seed = 0x654654;
	self->page_num = 32;
	self->start = 0xdead0UL << PAGE_SHIFT;
	self->end = self->start + (self->page_num << PAGE_SHIFT);

	fd = open(DEVICE_PATH, O_RDWR);
	ASSERT_GT(fd, 0);
	self->fd = fd;

	ASSERT_EQ(clean_all_pseudo_mm(fd), 0);
	ret = ioctl(fd, PSEUDO_MM_IOC_CREATE, (void *)(&self->pseudo_mm_id));
	ASSERT_TRUE(ret == 0 && self->pseudo_mm_id > 0);
	TH_LOG("process %d create pseudo_mm %d", getpid(), self->pseudo_mm_id);

	ret = fill_dax_device(37, self->page_num, self->seed);
	ASSERT_EQ(ret, 0);
}

FIXTURE_TEARDOWN(multi_page)
{
	close(self->fd);
}

TEST_F(multi_page, private_write_after_attach)
{
	int ret, ptc[2], ctp[2], i;
	pid_t pid, curr_pid;
	char *iter, pipe_buf;
	void *addr;
	struct pseudo_mm_attach_param attach_param;
	// SKIP(return, "");

	ret = add_mmap_to(self->fd, self->pseudo_mm_id, self->start, self->end,
			  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	ASSERT_EQ(ret, 0);
	ret = setup_anon_map_pt(self->fd, self->pseudo_mm_id, self->start,
				self->page_num << PAGE_SHIFT, 37);
	ASSERT_EQ(ret, 0);

	ASSERT_EQ(pipe(ptc), 0);
	ASSERT_EQ(pipe(ctp), 0);
	pid = fork();
	ASSERT_GE(pid, 0);
	curr_pid = getpid();
	// both child and parent need attach
	attach_param.id = self->pseudo_mm_id;
	attach_param.pid = curr_pid;
	ret = ioctl(self->fd, PSEUDO_MM_IOC_ATTACH, (void *)(&attach_param));
	ASSERT_EQ(ret, 0);
	TH_LOG("attach pseudo_mm_id %d succeed", self->pseudo_mm_id);

	if (pid == 0) {
		// child should not notice modification
		close(ptc[1]);
		close(ctp[0]);
		ASSERT_EQ(write(ctp[1], &pipe_buf, 1),
			  1); // notify parent that we have attached
		close(ctp[1]);
		ASSERT_EQ(read(ptc[0], &pipe_buf, 1), 1);
		close(ptc[0]);

		for (i = 0; i < self->page_num; i++) {
			addr = (void *)((unsigned long)self->start +
					(i << PAGE_SHIFT));
			ret = check_page_content(addr, self->seed);
		}
		TH_LOG("child %d finish checking", curr_pid);
		exit(EXIT_SUCCESS);
	} else {
		int status;
		// parent made some modification
		close(ptc[0]);
		close(ctp[1]);
		ASSERT_EQ(read(ctp[0], &pipe_buf, 1), 1);
		close(ctp[0]);
		for (iter = (char *)(self->start); iter < (char *)(self->end);
		     iter++)
			*iter = 'H';
		TH_LOG("parent %d finish modifying", curr_pid);
		ASSERT_EQ(write(ptc[1], &pipe_buf, 1), 1);
		close(ptc[1]);
		// wait for child to exit
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		ASSERT_TRUE(WIFEXITED(status));
		ASSERT_EQ(WEXITSTATUS(status), 0);
	}
}

TEST_F(multi_page, private_attach_after_write)
{
	int ret, pipe_fd[2], i;
	pid_t pid, curr_pid;
	char *iter, pipe_buf;
	void *addr;
	struct pseudo_mm_attach_param attach_param;
	// SKIP(return, "");

	ret = add_mmap_to(self->fd, self->pseudo_mm_id, self->start, self->end,
			  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	ASSERT_EQ(ret, 0);
	ret = setup_anon_map_pt(self->fd, self->pseudo_mm_id, self->start,
				self->page_num << PAGE_SHIFT, 37);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(pipe(pipe_fd), 0);
	pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		close(pipe_fd[1]);
		ASSERT_EQ(read(pipe_fd[0], &pipe_buf, 1), 1);
		close(pipe_fd[0]);
		// child should not notice modification
		curr_pid = getpid();
		attach_param.id = self->pseudo_mm_id;
		attach_param.pid = curr_pid;
		ret = ioctl(self->fd, PSEUDO_MM_IOC_ATTACH,
			    (void *)(&attach_param));
		ASSERT_EQ(ret, 0);
		for (i = 0; i < self->page_num; i++) {
			addr = (void *)((unsigned long)self->start +
					(i << PAGE_SHIFT));
			ret = check_page_content(addr, self->seed);
			ASSERT_EQ(ret, 0);
		}
		TH_LOG("child %d finish checking", getpid());
		exit(EXIT_SUCCESS);
	} else {
		int status;
		close(pipe_fd[0]);
		curr_pid = getpid();
		attach_param.id = self->pseudo_mm_id;
		attach_param.pid = curr_pid;
		ret = ioctl(self->fd, PSEUDO_MM_IOC_ATTACH,
			    (void *)(&attach_param));
		ASSERT_EQ(ret, 0);
		for (iter = (char *)(self->start); iter < (char *)(self->end);
		     iter++)
			*iter = 'X';
		ASSERT_EQ(write(pipe_fd[1], &pipe_buf, 1), 1);
		close(pipe_fd[1]);
		// wait for child to exit
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		ASSERT_TRUE(WIFEXITED(status));
		ASSERT_EQ(WEXITSTATUS(status), 0);
	}
}

// We create a vma like a stack (MAP_GROWSDOWN)
// and try to access the address below that vma.
// We expect that the vma can expand successfully.
TEST(stack_test)
{
	int fd, ret;
	int pseudo_mm_id;
	pid_t pid;
	const unsigned long seed = 0x823823;
	const int page_num = 6;
	const unsigned long start = 0xdead0UL << PAGE_SHIFT;
	const unsigned long end = start + (page_num << PAGE_SHIFT);

	fd = open(DEVICE_PATH, O_RDWR);
	ASSERT_GT(fd, 0);
	ASSERT_EQ(clean_all_pseudo_mm(fd), 0);
	ret = ioctl(fd, PSEUDO_MM_IOC_CREATE, (void *)(&pseudo_mm_id));
	ASSERT_TRUE(ret == 0 && pseudo_mm_id > 0);
	TH_LOG("process %d create pseudo_mm %d", getpid(), pseudo_mm_id);
	ret = fill_dax_device(256, page_num, seed);
	ASSERT_EQ(ret, 0);
	ret = add_mmap_to(fd, pseudo_mm_id, start, end,
			  MAP_ANONYMOUS | MAP_PRIVATE | MAP_GROWSDOWN, -1, 0);
	ASSERT_EQ(ret, 0);
	ret = setup_anon_map_pt(fd, pseudo_mm_id, start, page_num << PAGE_SHIFT,
				256);
	ASSERT_EQ(ret, 0);
	pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		struct pseudo_mm_attach_param attach_param;
		int i;
		char *ptr;
		attach_param.id = pseudo_mm_id;
		attach_param.pid = getpid();
		ret = ioctl(fd, PSEUDO_MM_IOC_ATTACH, (void *)(&attach_param));
		ASSERT_EQ(ret, 0);

		for (i = 0; i < page_num; i++) {
			ret = check_page_content(
				(void *)(start + i * PAGE_SIZE), seed);
			ASSERT_EQ(ret, 0);
		}
		// access address below `start`
		for (i = 1; i < 16; i++) {
			ptr = (char *)(start - i * PAGE_SIZE);
			*ptr = 'X';
		}
		exit(EXIT_SUCCESS);
	} else {
		int status;
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		ASSERT_TRUE(WIFEXITED(status));
		ASSERT_EQ(WEXITSTATUS(status), 0);
	}
}

TEST(dax_test)
{
	void *addr;
	int dax_fd, ret;
	const unsigned long seed = 0xdeadbeefUL;
	SKIP(return, "only used to test dax device");

	ret = fill_dax_device(0, 1, seed);
	ASSERT_EQ(ret, 0);

	dax_fd = open(DAX_DEVICE_PATH, O_RDWR);
	ASSERT_GE(dax_fd, 0);
	addr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, dax_fd,
		    0);
	ASSERT_NE(addr, MAP_FAILED);
	check_page_content(addr, seed);
}

TEST_HARNESS_MAIN
