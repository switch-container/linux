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
	unsigned long seed;
};

FIXTURE_SETUP(single_page_file)
{
	pid_t pid;
	int pipe_fd[2];

	self->filename = "single_page_file.img";
	self->seed = djb_hash(self->filename);
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
		TH_LOG("process %d create pseudo_mm %d", getpid(),
		       pseudo_mm_id);

		fd = create_and_fill_file(self->filename, PAGE_SIZE, 0);
		ASSERT_GE(fd, 0);

		ret = add_mmap_to(self->dev_fd, pseudo_mm_id, self->start,
				  self->end, MAP_PRIVATE, fd, 0);
		ASSERT_EQ(ret, 0);
		close(fd);
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
		ASSERT_GE(self->pseudo_mm_id, 0);
		close(pipe_fd[0]);
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		ASSERT_TRUE(WIFEXITED(status));
		ASSERT_EQ(WEXITSTATUS(status), 0);
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
	int ret;
	pid_t pid;
	struct pseudo_mm_attach_param attach_param;

	pid = getpid();
	attach_param.pid = pid;
	attach_param.id = self->pseudo_mm_id;
	ret = ioctl(self->dev_fd, PSEUDO_MM_IOC_ATTACH,
		    (void *)(&attach_param));
	ASSERT_EQ(ret, 0);

	ret = check_page_content((void *)self->start, self->seed);
	ASSERT_EQ(ret, 0);
}

TEST_F(single_page_file, independent_attachment_write)
{
	int ret, i;
	pid_t pid, curr_pid;
	char *iter;
	struct pseudo_mm_attach_param attach_param;

	// first fork then attach
	pid = fork();
	ASSERT_GE(pid, 0);

	curr_pid = getpid();
	attach_param.pid = curr_pid;
	attach_param.id = self->pseudo_mm_id;
	ret = ioctl(self->dev_fd, PSEUDO_MM_IOC_ATTACH,
		    (void *)(&attach_param));
	ASSERT_EQ(ret, 0);

	ret = check_page_content((void *)self->start, self->seed);
	ASSERT_EQ(ret, 0);

	if (pid == 0) {
		// child start to modify
		for (i = 0; i < PAGE_SIZE; i++) {
			iter = (char *)(self->start + i);
			*iter = 'X';
		}
		exit(EXIT_SUCCESS);
	} else {
		int status;
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		ASSERT_TRUE(WIFEXITED(status));
		ASSERT_EQ(WEXITSTATUS(status), 0);
	}
	/* 
	 * parent should not notice the modification made
	 * by child since it is private mapping.
	 */
	ret = check_page_content((void *)self->start, self->seed);
	ASSERT_EQ(ret, 0);
}

TEST_F(single_page_file, write)
{
	int ret, i;
	pid_t pid;
	char *iter;
	struct pseudo_mm_attach_param attach_param;

	// first attach then fork
	pid = getpid();
	attach_param.pid = pid;
	attach_param.id = self->pseudo_mm_id;
	ret = ioctl(self->dev_fd, PSEUDO_MM_IOC_ATTACH,
		    (void *)(&attach_param));
	ASSERT_EQ(ret, 0);

	pid = fork();
	ASSERT_GE(pid, 0);
	ret = check_page_content((void *)self->start, self->seed);
	ASSERT_EQ(ret, 0);

	if (pid == 0) {
		// child start to modify
		for (i = 0; i < PAGE_SIZE; i++) {
			iter = (char *)(self->start + i);
			*iter = 'X';
		}
		exit(EXIT_SUCCESS);
	} else {
		int status;
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		ASSERT_TRUE(WIFEXITED(status));
		ASSERT_EQ(WEXITSTATUS(status), 0);
	}
	/* 
	 * parent should not notice the modification made
	 * by child since MAP_PRIVATE.
	 */
	ret = check_page_content((void *)self->start, self->seed);
	ASSERT_EQ(ret, 0);
}

FIXTURE(single_page_shared_file)
{
	int dev_fd, pseudo_mm_id;
	unsigned long start, end;
	char *filename;
	unsigned long seed;
};

FIXTURE_SETUP(single_page_shared_file)
{
	pid_t pid;
	int pipe_fd[2];

	self->filename = "single_page_shared_file.img";
	self->seed = djb_hash(self->filename);
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
		TH_LOG("process %d create pseudo_mm %d", getpid(),
		       pseudo_mm_id);

		fd = create_and_fill_file(self->filename, PAGE_SIZE, 0);
		ASSERT_GE(fd, 0);

		ret = add_mmap_to(self->dev_fd, pseudo_mm_id, self->start,
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
		int status;
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		ASSERT_TRUE(WIFEXITED(status));
		ASSERT_EQ(WEXITSTATUS(status), 0);
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

	// first fork then attach
	pid = fork();
	ASSERT_GE(pid, 0);

	curr_pid = getpid();
	attach_param.pid = curr_pid;
	attach_param.id = self->pseudo_mm_id;
	ret = ioctl(self->dev_fd, PSEUDO_MM_IOC_ATTACH,
		    (void *)(&attach_param));
	ASSERT_EQ(ret, 0);

	ret = check_page_content((void *)self->start, self->seed);
	ASSERT_EQ(ret, 0);

	if (pid == 0) {
		// child start to modify
		for (i = 0; i < PAGE_SIZE; i++) {
			iter = (char *)(self->start + i);
			*iter = 'X';
		}
		exit(EXIT_SUCCESS);
	} else {
		int status;
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		ASSERT_TRUE(WIFEXITED(status));
		ASSERT_EQ(WEXITSTATUS(status), 0);
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

	// first attach then fork
	pid = getpid();
	attach_param.pid = pid;
	attach_param.id = self->pseudo_mm_id;
	ret = ioctl(self->dev_fd, PSEUDO_MM_IOC_ATTACH,
		    (void *)(&attach_param));
	ASSERT_EQ(ret, 0);
	pid = fork();
	ASSERT_GE(pid, 0);

	ret = check_page_content((void *)self->start, self->seed);
	ASSERT_EQ(ret, 0);
	if (pid == 0) {
		// child start to modify
		for (i = 0; i < PAGE_SIZE; i++) {
			iter = (char *)(self->start + i);
			*iter = 'X';
		}
		exit(EXIT_SUCCESS);
	} else {
		int status;
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		ASSERT_TRUE(WIFEXITED(status));
		ASSERT_EQ(WEXITSTATUS(status), 0);
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

TEST(multi_pages_with_offset)
{
	pid_t pid;
	int pipe_fd[2];
	const char *filename = "multi_pages_with_offset.img";
	unsigned long seed = djb_hash(filename);
	int page_num = 243;
	unsigned long start = 0xdead0UL << PAGE_SHIFT;
	unsigned long end = start + (page_num << PAGE_SHIFT);
	int dev_fd = open(DEVICE_PATH, O_RDWR);
	int pseudo_mm_id;
	struct pseudo_mm_attach_param param;
	int i, ret;

	ASSERT_GT(dev_fd, 0);
	ASSERT_EQ(clean_all_pseudo_mm(dev_fd), 0);
	// prepare file and pseudo_mm
	ASSERT_EQ(pipe(pipe_fd), 0);
	pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		int fd, ret;
		char ch;

		close(pipe_fd[0]);
		ret = ioctl(dev_fd, PSEUDO_MM_IOC_CREATE,
			    (void *)(&pseudo_mm_id));
		ASSERT_TRUE(ret == 0 && pseudo_mm_id > 0);
		TH_LOG("process %d create pseudo_mm %d", getpid(),
		       pseudo_mm_id);
		// we create a file in offset (page_num << PAGE_SHIFT)
		fd = create_and_fill_file(filename, page_num << PAGE_SHIFT,
					  page_num << PAGE_SHIFT);
		ASSERT_GE(fd, 0);
		// make sure that the front of the file is zeroed
		for (i = 0; i < (page_num << PAGE_SHIFT); i++) {
			ASSERT_EQ(pread(fd, &ch, 1, i), 1);
			ASSERT_EQ(ch, 0x0);
		}

		ret = add_mmap_to(dev_fd, pseudo_mm_id, start, end, MAP_PRIVATE,
				  fd, page_num << PAGE_SHIFT);
		ASSERT_EQ(ret, 0);
		close(fd);
		ASSERT_EQ(write(pipe_fd[1], &pseudo_mm_id,
				sizeof(pseudo_mm_id)),
			  sizeof(pseudo_mm_id));
		close(pipe_fd[1]);
		exit(EXIT_SUCCESS);
	} else {
		int status;
		close(pipe_fd[1]);
		ASSERT_EQ(read(pipe_fd[0], &pseudo_mm_id, sizeof(pseudo_mm_id)),
			  sizeof(pseudo_mm_id));
		ASSERT_GE(pseudo_mm_id, 0);
		close(pipe_fd[0]);
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		ASSERT_TRUE(WIFEXITED(status));
		ASSERT_EQ(WEXITSTATUS(status), 0);
	}

	// start attach
	param.pid = getpid();
	param.id = pseudo_mm_id;
	ret = ioctl(dev_fd, PSEUDO_MM_IOC_ATTACH, (void *)(&param));
	ASSERT_EQ(ret, 0);
	for (i = 0; i < page_num; i++) {
		ret = check_page_content((void *)(start + i * PAGE_SIZE), seed);
		ASSERT_EQ(ret, 0);
	}
}

TEST_HARNESS_MAIN
