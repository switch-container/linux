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
#define IMAGE_FILE "one-page.img"
#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)

int add_and_fill_anon_map_to(int fd, int img_fd, int pseudo_mm_id,
			     unsigned long start, unsigned long end,
			     unsigned long flags)
{
	int ret;
	struct pseudo_mm_add_map_param add_anon_param;
	struct pseudo_mm_fill_anon_param fill_anon_param;

	if (!(flags & MAP_ANONYMOUS))
		return -1;
	// user space allowed address is <= 0x7fff_ffff_ffff
	// for simplicity I hardcode the two address.
	// this two addresses MAYBE used (but often it is unlikely to be used)
	add_anon_param.id = pseudo_mm_id;
	add_anon_param.start = start;
	add_anon_param.end = end;
	add_anon_param.prot = PROT_READ | PROT_WRITE;
	add_anon_param.flags = flags;
	add_anon_param.fd = -1;
	add_anon_param.pgoff = 0;
	printf("add map start\n");
	fflush(stdout);
	ret = ioctl(fd, PSEUDO_MM_IOC_ADD_MAP, (void *)(&add_anon_param));
	printf("add map finish ret: %d\n", ret);
	fflush(stdout);
	if (ret)
		return ret;

	fill_anon_param.id = pseudo_mm_id;
	fill_anon_param.start = start;
	fill_anon_param.end = end;
	fill_anon_param.offset = 0;
	fill_anon_param.fd = img_fd;

	printf("fill anon start\n");
	fflush(stdout);
	ret = ioctl(fd, PSEUDO_MM_IOC_FILL_ANON, (void *)(&fill_anon_param));
	printf("fill anon finish: %d\n", ret);
	fflush(stdout);

	return ret;
}

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

	return;

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

/*
 * check_anon_page_content() - check the memory page content
 * @start: the start of page address (must aligned)
 *
 * Return 0 when check succeed.
 */
int check_anon_page_content(void *start)
{
	int i;
	char *iter;
	for (i = 0; i < PAGE_SIZE; i++) {
		iter = (char *)(start + i);
		if (*iter != ((i % 20) + 'a')) {
			printf("check_anon_page_content: expect %d find %d\n",
			       (i % 20) + 'a', *iter);
			return -1;
		}
	}
	return 0;
}

FIXTURE(single_page_anon)
{
	int pseudo_mm_id, img_fd, fd;
};

FIXTURE_SETUP(single_page_anon)
{
	// 1. create a pseudo_mm
	// 2. add an one-page anon mapping to pseudo_mm
	// 3. fill the memory content of this one-page mapping with a image file
	int ret, i;
	char ch;

	TH_LOG("test start pid %d ppid %d", getpid(), getppid());

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

	self->img_fd = open(IMAGE_FILE, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	ASSERT_GT(self->img_fd, 0)
	{
		TH_LOG("open image file " IMAGE_FILE " failed: %d!",
		       self->img_fd);
	}
	for (i = 0; i < PAGE_SIZE; i++) {
		ch = (i % 20) + 'a';
		ret = pwrite(self->img_fd, (void *)(&ch), 1, i);
		ASSERT_EQ(ret, 1);
	}
	fsync(self->img_fd);
}

FIXTURE_TEARDOWN(single_page_anon)
{
	close(self->fd);
	close(self->img_fd);
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
	ret = add_and_fill_anon_map_to(self->fd, self->img_fd,
				       self->pseudo_mm_id, start, end,
				       MAP_ANONYMOUS | MAP_PRIVATE);
	ASSERT_EQ(ret, 0);
	TH_LOG("add and fill anon map (#%lx - #%lx) finish", start, end);

	attach_param.id = self->pseudo_mm_id;
	attach_param.pid = pid;
	ret = ioctl(self->fd, PSEUDO_MM_IOC_ATTACH, (void *)(&attach_param));
	ASSERT_EQ(ret, 0);

	TH_LOG("attach succeed and start check anon page content");
	ret = check_anon_page_content((void *)start);
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
	ret = add_and_fill_anon_map_to(self->fd, self->img_fd,
				       self->pseudo_mm_id, start, end,
				       MAP_ANONYMOUS | MAP_PRIVATE);
	ASSERT_EQ(ret, 0)
	{
		TH_LOG("add and fill anon map (#%lx - #%lx) failed: %d", start,
		       end, ret);
	}

	attach_param.id = self->pseudo_mm_id;
	attach_param.pid = pid;
	ret = ioctl(self->fd, PSEUDO_MM_IOC_ATTACH, (void *)(&attach_param));
	ASSERT_NE(ret, 0)
	{
		TH_LOG("attach anon mapping to current process with conflict address succeed");
	}
}

TEST_F(single_page_anon, check_dax_device_content)
{
	int ret, pipe_fd[2];
	char pipe_buf;
	pid_t pid, curr_pid;
	const unsigned long start = 0xdead0UL << PAGE_SHIFT;
	const unsigned long end = start + PAGE_SIZE;
	struct pseudo_mm_attach_param attach_param;

	ASSERT_EQ(pipe(pipe_fd), 0);
	pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		int fd;
		void *addr;

		close(pipe_fd[1]);
		ASSERT_EQ(read(pipe_fd[0], &pipe_buf, 1), 1);
		close(pipe_fd[0]);
		fd = open("/dev/dax0.0", O_RDWR);
		ASSERT_GT(fd, 0);
		addr = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_SHARED, fd, 0);
		ASSERT_NE(addr, MAP_FAILED);
		TH_LOG("child mmap addr %#lx", (unsigned long)addr);
		ret = check_anon_page_content((void *)addr);
		ASSERT_EQ(ret, 0);
		TH_LOG("child check page content ret %d", ret);
		if (ret) {
			exit(EXIT_FAILURE);
		}
		exit(EXIT_SUCCESS);
	} else {
		int status;
		close(pipe_fd[0]);
		curr_pid = getpid();
		TH_LOG("try to add and fill anon map #%lx - #%lx", start, end);
		ret = add_and_fill_anon_map_to(self->fd, self->img_fd,
					       self->pseudo_mm_id, start, end,
					       MAP_ANONYMOUS | MAP_PRIVATE);
		ASSERT_EQ(ret, 0);
		TH_LOG("add and fill anon map (%#lx - %#lx) finish", start,
		       end);
		attach_param.id = self->pseudo_mm_id;
		attach_param.pid = curr_pid;
		ret = ioctl(self->fd, PSEUDO_MM_IOC_ATTACH,
			    (void *)(&attach_param));
		ASSERT_EQ(ret, 0);
		TH_LOG("attach succeed and start check anon page content");
		ret = check_anon_page_content((void *)start);
		ASSERT_EQ(ret, 0);
		ASSERT_EQ(write(pipe_fd[1], &pipe_buf, 1), 1);
		close(pipe_fd[1]);
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		ASSERT_TRUE(WIFEXITED(status));
		ASSERT_EQ(WEXITSTATUS(status), 0);
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
};

FIXTURE_SETUP(pseudo_mm_lifetime_simple)
{
	TH_LOG("test start pid %d ppid %d", getpid(), getppid());
	self->start = 0xdead0UL << PAGE_SHIFT;
	self->end = 0xdead1UL << PAGE_SHIFT;
	self->fd = open(DEVICE_PATH, O_RDWR);
	ASSERT_GT(self->fd, 0);
	ASSERT_EQ(clean_all_pseudo_mm(self->fd), 0);
}

FIXTURE_TEARDOWN(pseudo_mm_lifetime_simple)
{
	close(self->fd);
}

FIXTURE_VARIANT(pseudo_mm_lifetime_simple)
{
	unsigned long flags;
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
	int ret, pseudo_mm_id, img_fd, i, pipe_fd[2];
	char ch;

	/*
	 * one process create, fill pseudo_mm then exit
	 */
	ASSERT_EQ(pipe(pipe_fd), 0);
	pid = fork();
	if (pid == 0) {
		close(pipe_fd[0]);
		img_fd = open(IMAGE_FILE, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
		ASSERT_GT(img_fd, 0);
		for (i = 0; i < PAGE_SIZE; i++) {
			ch = (i % 20) + 'a';
			ret = pwrite(img_fd, (void *)(&ch), 1, i);
			ASSERT_EQ(ret, 1);
		}
		fsync(img_fd);
		ret = ioctl(self->fd, PSEUDO_MM_IOC_CREATE,
			    (void *)(&pseudo_mm_id));
		TH_LOG("process %d create pseudo_mm %d", getpid(),
		       pseudo_mm_id);
		ASSERT_EQ(ret, 0);
		ASSERT_GE(pseudo_mm_id, 1);

		ret = add_and_fill_anon_map_to(self->fd, img_fd, pseudo_mm_id,
					       self->start, self->end,
					       variant->flags);
		ASSERT_EQ(ret, 0);
		close(img_fd);
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

	ret = check_anon_page_content((void *)self->start);
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
	int pipe_fd[2];
	pid_t pid;
	TH_LOG("test start pid %d ppid %d", getpid(), getppid());
	// create a pseudo_mm
	self->start = 0xdead0UL << PAGE_SHIFT;
	self->end = 0xdead1UL << PAGE_SHIFT;

	self->fd = open(DEVICE_PATH, O_RDWR);
	ASSERT_GT(self->fd, 0);

	ASSERT_EQ(clean_all_pseudo_mm(self->fd), 0);

	ASSERT_EQ(pipe(pipe_fd), 0);
	pid = fork();
	if (pid == 0) {
		int img_fd, ret, i;
		char ch;
		int pseudo_mm_id;

		close(pipe_fd[0]);
		ret = ioctl(self->fd, PSEUDO_MM_IOC_CREATE,
			    (void *)(&pseudo_mm_id));
		ASSERT_TRUE(ret == 0 && pseudo_mm_id > 0);
		TH_LOG("process %d create pseudo_mm %d", getpid(),
		       pseudo_mm_id);

		img_fd = open(IMAGE_FILE, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
		ASSERT_GT(img_fd, 0);
		for (i = 0; i < PAGE_SIZE; i++) {
			ch = (i % 20) + 'a';
			ret = pwrite(img_fd, (void *)(&ch), 1, i);
			ASSERT_EQ(ret, 1);
		}
		fsync(img_fd);

		ret = add_and_fill_anon_map_to(self->fd, img_fd, pseudo_mm_id,
					       self->start, self->end,
					       variant->flags);
		ASSERT_EQ(ret, 0);
		close(img_fd);
		ASSERT_EQ(write(pipe_fd[1], &pseudo_mm_id,
				sizeof(pseudo_mm_id)),
			  sizeof(pseudo_mm_id));
		close(pipe_fd[1]);
		exit(EXIT_SUCCESS);
	} else {
		int status;
		close(pipe_fd[1]);
		ASSERT_EQ(read(pipe_fd[0], &self->pseudo_mm_id,
			       sizeof(self->pseudo_mm_id)),
			  sizeof(self->pseudo_mm_id));
		ASSERT_GT(self->pseudo_mm_id, 0);
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		ASSERT_TRUE(WIFEXITED(status));
		ASSERT_EQ(WEXITSTATUS(status), 0);
	}
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

	ret = check_anon_page_content((void *)self->start);
	ASSERT_EQ(ret, 0);

	if (pid == 0) {
		// child should not notice modification
		close(ptc[1]);
		close(ctp[0]);
		ASSERT_EQ(write(ctp[1], &buf, 1),
			  1); // notify parent to start modification
		ASSERT_EQ(read(ptc[0], &buf, 1),
			  1); // wait for parent's modification
		close(ptc[0]);
		// make sure child does not see parent's modification
		ret = check_anon_page_content((void *)self->start);
		buf = ret == 0 ? 0 : 'e'; // 0 means succeed, 'e' means error
		ASSERT_EQ(write(ctp[1], &buf, 1), 1);
		close(ctp[1]);
		exit(EXIT_SUCCESS);
	} else {
		int status;
		// parent modify memory content
		ASSERT_EQ(read(ctp[0], &buf, 1),
			  1); // wait for child's preparation
		close(ptc[0]);
		close(ctp[1]);
		for (i = 0; i < PAGE_SIZE; i++) {
			iter = (char *)(self->start + i);
			*iter = 'X';
		}
		ASSERT_EQ(write(ptc[1], &buf, 1), 1);
		close(ptc[1]);
		// parent read from pipe when child succeed;
		ASSERT_EQ(read(ctp[0], &buf, 1), 1);
		close(ctp[0]);
		ASSERT_EQ(buf, 0);
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		ASSERT_TRUE(WIFEXITED(status));
		ASSERT_EQ(WEXITSTATUS(status), 0);
	}
}

FIXTURE(multi_page)
{
	int fd, img_fd, pseudo_mm_id;
	unsigned long start, end;
	int page_num;
};

FIXTURE_SETUP(multi_page)
{
	int fd, img_fd, ret, i;
	char ch;

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

	img_fd = open(IMAGE_FILE, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	ASSERT_GT(img_fd, 0);
	self->img_fd = img_fd;
	for (i = 0; i < self->page_num * PAGE_SIZE; i++) {
		ch = (i % 20) + 'a';
		ret = pwrite(img_fd, (void *)(&ch), 1, i);
		ASSERT_EQ(ret, 1);
	}
	fsync(img_fd);
}

FIXTURE_TEARDOWN(multi_page)
{
	close(self->img_fd);
	unlink(IMAGE_FILE);
	close(self->fd);
}

TEST_F(multi_page, private_write_after_attach)
{
	int ret, ptc[2], ctp[2], i;
	pid_t pid, curr_pid;
	char *iter, pipe_buf;
	struct pseudo_mm_attach_param attach_param;

	ret = add_and_fill_anon_map_to(self->fd, self->img_fd,
				       self->pseudo_mm_id, self->start,
				       self->end, MAP_ANONYMOUS | MAP_PRIVATE);
	TH_LOG("add and fill pseudo_mm_id %d succeed", self->pseudo_mm_id);
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
		for (i = 0; i < self->page_num * PAGE_SHIFT; i++) {
			iter = (char *)(self->start + i);
			ASSERT_EQ(*iter, (i % 20) + 'a');
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
	struct pseudo_mm_attach_param attach_param;

	ret = add_and_fill_anon_map_to(self->fd, self->img_fd,
				       self->pseudo_mm_id, self->start,
				       self->end, MAP_ANONYMOUS | MAP_PRIVATE);
	ASSERT_EQ(ret, 0);
	TH_LOG("add and fill pseudo_mm_id %d succeed", self->pseudo_mm_id);
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
		for (i = 0; i < self->page_num * PAGE_SHIFT; i++) {
			iter = (char *)(self->start + i);
			ASSERT_EQ(*iter, (i % 20) + 'a');
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

/*
 * 1. one process A attach a shared anon pseudo_mm.
 * 2. A fork() a child process B.
 * 3. A modify the memory content in the shared anon pseudo_mm area.
 * 4. B should notice those modifications.
 */
TEST_F(multi_page, shared)
{
	int ret, pipe_fd[2];
	pid_t pid;
	char *iter, pipe_buf;
	struct pseudo_mm_attach_param attach_param;

	SKIP(NULL, "skip multi_page_shared (for now do not support)");

	TH_LOG("test start pid %d ppid %d", getpid(), getppid());

	ret = add_and_fill_anon_map_to(self->fd, self->img_fd,
				       self->pseudo_mm_id, self->start,
				       self->end, MAP_ANONYMOUS | MAP_SHARED);
	TH_LOG("add and fill pseudo_mm_id %d succeed", self->pseudo_mm_id);
	ASSERT_EQ(ret, 0);

	pid = getpid();
	// both child and parent need attach
	attach_param.id = self->pseudo_mm_id;
	attach_param.pid = pid;
	ret = ioctl(self->fd, PSEUDO_MM_IOC_ATTACH, (void *)(&attach_param));
	ASSERT_EQ(ret, 0);
	TH_LOG("attach pseudo_mm_id %d succeed", self->pseudo_mm_id);

	ASSERT_EQ(pipe(pipe_fd), 0);
	pid = fork();
	ASSERT_GE(pid, 0);

	if (pid == 0) {
		// child
		close(pipe_fd[1]);
		ASSERT_EQ(read(pipe_fd[0], &pipe_buf, 1), 1);
		close(pipe_fd[0]);
		for (iter = (char *)(self->start); iter < (char *)(self->end);
		     iter++)
			ASSERT_EQ(*iter, 'H');
		TH_LOG("child %d finish checking", getpid());
		exit(EXIT_SUCCESS);
	} else {
		int status;
		// parent
		close(pipe_fd[0]);
		for (iter = (char *)(self->start); iter < (char *)(self->end);
		     iter++)
			*iter = 'H';
		TH_LOG("parent %d finish modifying", getpid());
		ASSERT_EQ(write(pipe_fd[1], &pipe_buf, 1), 1);
		close(pipe_fd[1]);
		// wait for child to exit
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		ASSERT_TRUE(WIFEXITED(status));
		ASSERT_EQ(WEXITSTATUS(status), 0);
	}
}

TEST_HARNESS_MAIN
