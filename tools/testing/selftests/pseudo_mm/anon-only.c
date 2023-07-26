#include <assert.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
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
	struct pseudo_mm_add_anon_param add_anon_param;
	struct pseudo_mm_fill_anon_param fill_anon_param;

	// user space allowed address is <= 0x7fff_ffff_ffff
	// for simplicity I hardcode the two address.
	// this two addresses MAYBE used (but often it is unlikely to be used)
	add_anon_param.id = pseudo_mm_id;
	add_anon_param.start = start;
	add_anon_param.end = end;
	add_anon_param.prot = PROT_READ | PROT_WRITE;
	add_anon_param.flags = flags;
	ret = ioctl(fd, PSEUDO_MM_IOC_ADD_ANON, (void *)(&add_anon_param));
	if (ret)
		return ret;

	fill_anon_param.id = pseudo_mm_id;
	fill_anon_param.start = start;
	fill_anon_param.end = end;
	fill_anon_param.offset = 0;

	fill_anon_param.fd = img_fd;

	ret = ioctl(fd, PSEUDO_MM_IOC_FILL_ANON, (void *)(&fill_anon_param));

	return ret;
}

TEST(pseudo_mm_create)
{
	int i, j, fd, ret;
	int *pseudo_mm_ids;
	const int size = 128;

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
		if (*iter != ((i % 20) + 'a'))
			return -1;
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

	self->fd = open(DEVICE_PATH, O_RDWR);
	ASSERT_GT(self->fd, 0)
	{
		TH_LOG("open misc driver " DEVICE_PATH " failed: %d!",
		       self->fd);
	}

	ret = ioctl(self->fd, PSEUDO_MM_IOC_CREATE,
		    (void *)(&self->pseudo_mm_id));
	ASSERT_TRUE(ret == 0 && self->pseudo_mm_id > 0)
	{
		TH_LOG("create paseudo_mm failed: ret %d pseudo_mm_id %d!", ret,
		       self->pseudo_mm_id);
	}

	TH_LOG("succeed to create a pseudo_mm (id = %d).", self->pseudo_mm_id);

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
	int ret;
	ret = ioctl(self->fd, PSEUDO_MM_IOC_DELETE,
		    (void *)(&self->pseudo_mm_id));
	EXPECT_EQ(ret, 0)
	{
		TH_LOG("delete pseudo_mm %d failed: %d!", self->pseudo_mm_id,
		       ret);
	}
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
	ASSERT_EQ(ret, 0)
	{
		TH_LOG("add and fill anon map (#%lx - #%lx) failed: %d", start,
		       end, ret);
	}

	attach_param.id = self->pseudo_mm_id;
	attach_param.pid = pid;
	ret = ioctl(self->fd, PSEUDO_MM_IOC_ATTACH, (void *)(&attach_param));
	ASSERT_EQ(ret, 0)
	{
		TH_LOG("attach anon mapping to current process failed: %d!",
		       ret);
	}

	ret = check_anon_page_content((void *)start);
	ASSERT_EQ(ret, 0)
	{
		TH_LOG("check anon page content at #%lx failed", start);
	}

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

FIXTURE(single_page_anon_multi_attach)
{
	int pseudo_mm_id, img_fd, fd;
};

FIXTURE_VARIANT(single_page_anon_multi_attach)
{
	unsigned long flags;
};

FIXTURE_VARIANT_ADD(single_page_anon_multi_attach, private){
	.flags = MAP_ANONYMOUS | MAP_PRIVATE,
};

FIXTURE_VARIANT_ADD(single_page_anon_multi_attach, shared){
	.flags = MAP_ANONYMOUS | MAP_SHARED,
};

FIXTURE_SETUP(single_page_anon_multi_attach)
{
	// 1. create a pseudo_mm
	// 2. add an one-page anon mapping to pseudo_mm
	// 3. fill the memory content of this one-page mapping with a image file
	int ret, i;
	char ch;

	self->fd = open(DEVICE_PATH, O_RDWR);
	ASSERT_GT(self->fd, 0)
	{
		TH_LOG("open misc driver " DEVICE_PATH " failed: %d!",
		       self->fd);
	}

	ret = ioctl(self->fd, PSEUDO_MM_IOC_CREATE,
		    (void *)(&self->pseudo_mm_id));
	ASSERT_TRUE(ret == 0 && self->pseudo_mm_id > 0)
	{
		TH_LOG("create paseudo_mm failed: ret %d pseudo_mm_id %d!", ret,
		       self->pseudo_mm_id);
	}

	TH_LOG("succeed to create a pseudo_mm (id = %d).", self->pseudo_mm_id);

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

FIXTURE_TEARDOWN(single_page_anon_multi_attach)
{
	int ret;
	ret = ioctl(self->fd, PSEUDO_MM_IOC_DELETE,
		    (void *)(&self->pseudo_mm_id));
	EXPECT_EQ(ret, 0)
	{
		TH_LOG("delete pseudo_mm %d failed: %d!", self->pseudo_mm_id,
		       ret);
	}
	close(self->fd);
	close(self->img_fd);
}

TEST_F(single_page_anon_multi_attach, one_writer_one_reader)
{
	// ctp means child(w)-to-parent(r) pipe
	// ptc means parent(r)-to-child(w) pipe
	int ret, i, ctp[2], ptc[2];
	char buf, *iter;
	pid_t pid, curr_pid;
	const unsigned long start = 0xdead0UL << PAGE_SHIFT;
	const unsigned long end = start + PAGE_SIZE;
	struct pseudo_mm_attach_param attach_param;

	TH_LOG("try to add and fill anon map #%lx - #%lx", start, end);
	ret = add_and_fill_anon_map_to(self->fd, self->img_fd,
				       self->pseudo_mm_id, start, end,
				       variant->flags);
	ASSERT_EQ(ret, 0)
	{
		TH_LOG("add and fill anon map (#%lx - #%lx) failed: %d", start,
		       end, ret);
	}

	ASSERT_EQ(pipe(ctp), 0);
	ASSERT_EQ(pipe(ptc), 0);
	pid = fork();
	ASSERT_GE(pid, 0);
	curr_pid = getpid();

	attach_param.id = self->pseudo_mm_id;
	attach_param.pid = curr_pid;
	ASSERT_NE(fcntl(self->fd, F_GETFD), -1);
	ret = ioctl(self->fd, PSEUDO_MM_IOC_ATTACH, (void *)(&attach_param));
	ASSERT_EQ(ret, 0)
	{
		TH_LOG("attach anon mapping to current process (%d) failed: %d!",
		       curr_pid, errno);
	}

	ret = check_anon_page_content((void *)start);
	ASSERT_EQ(ret, 0)
	{
		TH_LOG("process %d check anon page content at #%lx failed",
		       curr_pid, start);
	}

	TH_LOG("process %d succeed to attach pseudo_mm to current process and check its content.",
	       curr_pid);

	if (pid == 0) {
		// child
		close(ptc[1]);
		close(ctp[0]);
		ASSERT_EQ(write(ctp[1], &buf, 1), 1); // notify parent to start modification
		ASSERT_EQ(read(ptc[0], &buf, 1), 1);	// wait for parent's modification
		close(ptc[0]);
		// make sure child does not see parent's modification
		ret = check_anon_page_content((void *)start);
		buf = ret == 0 ? 0 : 'e';	// 0 means succeed, 'e' means error
		ASSERT_EQ(write(ctp[1], &buf, 1), 1);
		close(ctp[1]);
		exit(EXIT_SUCCESS);
	} else {
		// parent
		ASSERT_EQ(read(ctp[0], &buf, 1), 1);	// wait for child's preparation
		close(ptc[0]);
		close(ctp[1]);
		for (i = 0; i < PAGE_SIZE; i++) {
			iter = (char *)(start + i);
			*iter = 'X';
		}
		ASSERT_EQ(write(ptc[1], &buf, 1), 1);
		close(ptc[1]);
		// parent read from pipe when child succeed;
		ASSERT_EQ(read(ctp[0], &buf, 1), 1);
		close(ctp[0]);
		ASSERT_EQ(buf, 0)
		{
			TH_LOG("child failed to check content after parent's modification!");
		}
	}
}

TEST_HARNESS_MAIN
