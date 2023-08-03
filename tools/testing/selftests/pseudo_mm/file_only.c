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

int create_and_fill_file(const char *path, size_t size)
{
	int fd, ret;
	size_t i;
	char ch;
	size = (size + PAGE_SIZE - 1) & (~(PAGE_SIZE - 1));
	fd = open(path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
	if (fd < 0)
		return fd;
	for (i = 0; i < size; i++) {
		ch = (i % 30) + 'A';
		// printf("pwrite %lu to file %s\n", i, path);
		ret = pwrite(fd, &ch, 1, i);
		if (ret != 1)
			return -1;
	}
	fsync(fd);
	return fd;
}

int add_file_map_to(int pseudo_mm_id, int dev_fd, unsigned long start,
		    unsigned long end, unsigned long flags, int fd, off_t pgoff)
{
	struct pseudo_mm_add_map_param add_map_param;

	// user space allowed address is <= 0x7fff_ffff_ffff
	// for simplicity I hardcode the two address.
	// this two addresses MAYBE used (but often it is unlikely to be used)
	add_map_param.id = pseudo_mm_id;
	add_map_param.start = start;
	add_map_param.end = end;
	add_map_param.prot = PROT_READ | PROT_WRITE;
	add_map_param.flags = flags;
	add_map_param.fd = fd;
	add_map_param.pgoff = pgoff;
	return ioctl(dev_fd, PSEUDO_MM_IOC_ADD_MAP, (void *)(&add_map_param));
}

/*
 * @fd: the fd of pseudo_mm device
 */
int clean_all_pseudo_mm(int fd)
{
	// int pseudo_mm_id = -1;
	// return ioctl(fd, PSEUDO_MM_IOC_DELETE, (void *)(&pseudo_mm_id));
	return 0;
}

FIXTURE(single_page_file)
{
	int dev_fd, pseudo_mm_id;
	unsigned long start, end;
	char *filename;
};

FIXTURE_SETUP(single_page_file)
{
	pid_t pid;
	int pipe_fd[2];

	self->filename = "single_page.img";
	self->start = 0xdead0UL << PAGE_SHIFT;
	self->end = 0xdead1UL << PAGE_SHIFT;
	self->dev_fd = open(DEVICE_PATH, O_RDWR);
	ASSERT_GT(self->dev_fd, 0);
	ASSERT_EQ(clean_all_pseudo_mm(self->dev_fd), 0);

	ASSERT_EQ(pipe(pipe_fd), 0);
	pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		int pseudo_mm_id, fd, ret;

		close(pipe_fd[0]);
		ret = ioctl(self->dev_fd, PSEUDO_MM_IOC_CREATE,
			    (void *)(&pseudo_mm_id));
		ASSERT_TRUE(ret == 0 && pseudo_mm_id > 0);
		TH_LOG("process %d create pseudo_mm %d", getpid(), pseudo_mm_id);

		fd = create_and_fill_file(self->filename, PAGE_SIZE);
		ASSERT_GE(fd, 0);

		ret = add_file_map_to(pseudo_mm_id, self->dev_fd, self->start,
				      self->end, MAP_PRIVATE, fd, 0);
		ASSERT_EQ(ret, 0);
		close(fd);
		ASSERT_EQ(write(pipe_fd[1], &pseudo_mm_id,
				sizeof(pseudo_mm_id)),
			  sizeof(pseudo_mm_id));
		close(pipe_fd[1]);
		exit(EXIT_SUCCESS);
	} else {
		close(pipe_fd[1]);
		ASSERT_EQ(read(pipe_fd[0], &self->pseudo_mm_id,
			       sizeof(self->pseudo_mm_id)),
			  sizeof(self->pseudo_mm_id));
		ASSERT_GE(self->pseudo_mm_id, 0);
		close(pipe_fd[0]);
		ASSERT_EQ(waitpid(pid, NULL, 0), pid);
	}
}

FIXTURE_TEARDOWN(single_page_file)
{
	close(self->dev_fd);
	ASSERT_EQ(unlink(self->filename), 0);
}

// 1. one process create a pseudo_mm, filled with file-backed content then exit
// 2. one process attach the pseudo_mm and check its content with file.
TEST_F(single_page_file, read_only)
{
	int ret, i;
	pid_t pid;
	char *iter;
	struct pseudo_mm_attach_param attach_param;

	pid = getpid();
	attach_param.pid = pid;
	attach_param.id = self->pseudo_mm_id;
	ret = ioctl(self->dev_fd, PSEUDO_MM_IOC_ATTACH,
		    (void *)(&attach_param));
	ASSERT_EQ(ret, 0);

	for (i = 0; i < PAGE_SIZE; i++) {
		iter = (char *)(self->start + i);
		ASSERT_EQ(*iter, (i % 30) + 'A');
	}
}

TEST_F(single_page_file, independent_attachment_write)
{
	int ret, i;
	pid_t pid, curr_pid;
	char *iter;
	struct pseudo_mm_attach_param attach_param;

	pid = fork();
	ASSERT_GE(pid, 0);

	curr_pid = getpid();
	attach_param.pid = curr_pid;
	attach_param.id = self->pseudo_mm_id;
	ret = ioctl(self->dev_fd, PSEUDO_MM_IOC_ATTACH,
		    (void *)(&attach_param));
	ASSERT_EQ(ret, 0);

	for (i = 0; i < PAGE_SIZE; i++) {
		iter = (char *)(self->start + i);
		ASSERT_EQ(*iter, (i % 30) + 'A');
	}

	if (pid == 0) {
		// child start to modify
		for (i = 0; i < PAGE_SIZE; i++) {
			iter = (char *)(self->start + i);
			*iter = 'X';
		}
		exit(EXIT_SUCCESS);
	} else {
		ASSERT_EQ(waitpid(pid, NULL, 0), pid);
	}
	/* 
	 * parent should not notice the modification made
	 * by child since they are independent attachment.
	 */
	for (i = 0; i < PAGE_SIZE; i++) {
		iter = (char *)(self->start + i);
		ASSERT_EQ(*iter, (i % 30) + 'A');
	}
}

TEST_F(single_page_file, write)
{
	int ret, i;
	pid_t pid;
	char *iter;
	struct pseudo_mm_attach_param attach_param;

	pid = getpid();
	attach_param.pid = pid;
	attach_param.id = self->pseudo_mm_id;
	ret = ioctl(self->dev_fd, PSEUDO_MM_IOC_ATTACH,
		    (void *)(&attach_param));
	ASSERT_EQ(ret, 0);

	pid = fork();
	ASSERT_GE(pid, 0);
	for (i = 0; i < PAGE_SIZE; i++) {
		iter = (char *)(self->start + i);
		ASSERT_EQ(*iter, (i % 30) + 'A');
	}

	if (pid == 0) {
		// child start to modify
		for (i = 0; i < PAGE_SIZE; i++) {
			iter = (char *)(self->start + i);
			*iter = 'X';
		}
		exit(EXIT_SUCCESS);
	} else {
		ASSERT_EQ(waitpid(pid, NULL, 0), pid);
	}
	/* 
	 * parent should not notice the modification made
	 * by child since MAP_PRIVATE.
	 */
	for (i = 0; i < PAGE_SIZE; i++) {
		iter = (char *)(self->start + i);
		ASSERT_EQ(*iter, (i % 30) + 'A');
	}
}

FIXTURE(single_page_shared_file)
{
	int dev_fd, pseudo_mm_id;
	unsigned long start, end;
	char *filename;
};

FIXTURE_SETUP(single_page_shared_file)
{
	pid_t pid;
	int pipe_fd[2];

	self->filename = "single_page.img";
	self->start = 0xdead0UL << PAGE_SHIFT;
	self->end = 0xdead1UL << PAGE_SHIFT;
	self->dev_fd = open(DEVICE_PATH, O_RDWR);
	ASSERT_GT(self->dev_fd, 0);
	ASSERT_EQ(clean_all_pseudo_mm(self->dev_fd), 0);
	ASSERT_EQ(pipe(pipe_fd), 0);
	pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		int pseudo_mm_id, fd, ret;

		close(pipe_fd[0]);
		ret = ioctl(self->dev_fd, PSEUDO_MM_IOC_CREATE,
			    (void *)(&pseudo_mm_id));
		ASSERT_TRUE(ret == 0 && pseudo_mm_id > 0);
		TH_LOG("process %d create pseudo_mm %d", getpid(), pseudo_mm_id);

		fd = create_and_fill_file(self->filename, PAGE_SIZE);
		ASSERT_GE(fd, 0);

		ret = add_file_map_to(pseudo_mm_id, self->dev_fd, self->start,
				      self->end, MAP_SHARED, fd, 0);
		ASSERT_EQ(ret, 0);
		close(fd);
		ASSERT_EQ(write(pipe_fd[1], &pseudo_mm_id,
				sizeof(pseudo_mm_id)),
			  sizeof(pseudo_mm_id));
		close(pipe_fd[1]);
		exit(EXIT_SUCCESS);
	} else {
		close(pipe_fd[1]);
		ASSERT_EQ(read(pipe_fd[0], &self->pseudo_mm_id,
			       sizeof(self->pseudo_mm_id)),
			  sizeof(self->pseudo_mm_id));
		ASSERT_GE(self->pseudo_mm_id, 0);
		close(pipe_fd[0]);
		ASSERT_EQ(waitpid(pid, NULL, 0), pid);
	}
}

FIXTURE_TEARDOWN(single_page_shared_file)
{
	close(self->dev_fd);
	ASSERT_EQ(unlink(self->filename), 0);
}

TEST_F(single_page_shared_file, independent_attachment_write)
{
	int ret, i;
	pid_t pid, curr_pid;
	char *iter;
	struct pseudo_mm_attach_param attach_param;

	pid = fork();
	ASSERT_GE(pid, 0);

	curr_pid = getpid();
	attach_param.pid = curr_pid;
	attach_param.id = self->pseudo_mm_id;
	ret = ioctl(self->dev_fd, PSEUDO_MM_IOC_ATTACH,
		    (void *)(&attach_param));
	ASSERT_EQ(ret, 0);

	for (i = 0; i < PAGE_SIZE; i++) {
		iter = (char *)(self->start + i);
		ASSERT_EQ(*iter, (i % 30) + 'A');
	}

	if (pid == 0) {
		// child start to modify
		for (i = 0; i < PAGE_SIZE; i++) {
			iter = (char *)(self->start + i);
			*iter = 'X';
		}
		exit(EXIT_SUCCESS);
	} else {
		ASSERT_EQ(waitpid(pid, NULL, 0), pid);
	}
	/* 
	 * parent should notice the modification made
	 * by child. (caused by MAP_SHARED)
	 * They share the same file though they are
	 * independent attachment.
	 */
	for (i = 0; i < PAGE_SIZE; i++) {
		iter = (char *)(self->start + i);
		ASSERT_EQ(*iter, 'X');
	}
}

TEST_F(single_page_shared_file, write)
{
	int ret, i;
	pid_t pid;
	char *iter;
	struct pseudo_mm_attach_param attach_param;

	pid = getpid();
	attach_param.pid = pid;
	attach_param.id = self->pseudo_mm_id;
	ret = ioctl(self->dev_fd, PSEUDO_MM_IOC_ATTACH,
		    (void *)(&attach_param));
	ASSERT_EQ(ret, 0);
	pid = fork();
	ASSERT_GE(pid, 0);

	for (i = 0; i < PAGE_SIZE; i++) {
		iter = (char *)(self->start + i);
		ASSERT_EQ(*iter, (i % 30) + 'A');
	}
	if (pid == 0) {
		// child start to modify
		for (i = 0; i < PAGE_SIZE; i++) {
			iter = (char *)(self->start + i);
			*iter = 'X';
		}
		exit(EXIT_SUCCESS);
	} else {
		ASSERT_EQ(waitpid(pid, NULL, 0), pid);
	}
	/* 
	 * parent should notice the modification made
	 * by child. (caused by MAP_SHARED)
	 */
	for (i = 0; i < PAGE_SIZE; i++) {
		iter = (char *)(self->start + i);
		ASSERT_EQ(*iter, 'X');
	}
}

TEST_HARNESS_MAIN
