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

void gen_filename(int id, const char *title, char *buf)
{
	sprintf(buf, "%s-%d", title, id);
}

TEST(mixed_mapping)
{
	int fd, ret, i;
	int pseudo_mm_id;
	pid_t pid;
	unsigned long page_num, dax_pgoff = 0, vaddr, anon_final_addr;
	const unsigned long seed = 0xabcabc;
	const unsigned long start = 0xdead0UL << PAGE_SHIFT;
	const int anon_num = 16;
	const int file_num = 8;
	char filename[256];
	unsigned long *file_page_nums;
	struct pseudo_mm_attach_param attach_param;

	file_page_nums = calloc(file_num, sizeof(unsigned long));
	ASSERT_NE(file_page_nums, NULL);
	fd = open(DEVICE_PATH, O_RDWR);
	ASSERT_GT(fd, 0);
	// ASSERT_EQ(clean_all_pseudo_mm(fd), 0);
	ret = ioctl(fd, PSEUDO_MM_IOC_CREATE, (void *)(&pseudo_mm_id));
	ASSERT_TRUE(ret == 0 && pseudo_mm_id > 0);
	ASSERT_EQ(ret, 0);

	vaddr = start;
	for (int i = 0; i < anon_num; i++) {
		page_num = random() % 32 + 1;
		ret = fill_dax_device(dax_pgoff, page_num, seed);
		ASSERT_EQ(ret, 0);
		ret = add_mmap_to(fd, pseudo_mm_id, vaddr,
				  vaddr + (page_num << PAGE_SHIFT),
				  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		ASSERT_EQ(ret, 0);
		ret = setup_anon_map_pt(fd, pseudo_mm_id, vaddr,
					page_num << PAGE_SHIFT, dax_pgoff);
		ASSERT_EQ(ret, 0);

		dax_pgoff += page_num;
		vaddr += page_num << PAGE_SHIFT;
	}

	anon_final_addr = vaddr;

	for (int i = 0; i < file_num; i++) {
		int pgoff;
		unsigned long flag;
		int file_fd;
		page_num = random() % 64 + 1;
		gen_filename(i, "mixed_mapping", filename);
		pgoff = random() % 32;
		// create_and_fill_file() will return a fd if succeed
		file_fd = create_and_fill_file(filename, page_num << PAGE_SHIFT,
					       pgoff << PAGE_SHIFT);
		ASSERT_GE(file_fd, 0);
		flag = (random() % 2 == 0) ? MAP_PRIVATE : MAP_SHARED;
		ret = add_mmap_to(fd, pseudo_mm_id, vaddr,
				  vaddr + (page_num << PAGE_SHIFT), flag,
				  file_fd, pgoff << PAGE_SHIFT);
		ASSERT_EQ(ret, 0);
		close(file_fd);

		TH_LOG("file %s page num %ld vaddr start at %#lx", filename,
		       page_num, vaddr);
		vaddr += page_num << PAGE_SHIFT;
		file_page_nums[i] = page_num;
	}

	// we attach multiple times
	for (i = 0; i < 16; i++) {
		pid = fork();
		ASSERT_GE(pid, 0);
		if (pid == 0) {
			unsigned long ptr;
			int j, k;

			attach_param.id = pseudo_mm_id;
			attach_param.pid = getpid();
			ret = ioctl(fd, PSEUDO_MM_IOC_ATTACH,
				    (void *)(&attach_param));
			ASSERT_EQ(ret, 0);
			// first we check anonymous mapping
			for (ptr = start; ptr != anon_final_addr;
			     ptr += PAGE_SIZE) {
				ret = check_page_content((void *)ptr, seed);
				ASSERT_EQ(ret, 0);
			}
			TH_LOG("anon mapping (final = %#lx) check succeed",
			       anon_final_addr);
			// then we check file mapping
			// (NOTE: the seed of file mapping is not `seed`)
			// we have record the number of pages in each file mapping
			//
			// j is the index of file mapping
			// k is the current page index in that mapping
			for (j = 0; j < file_num; j++) {
				gen_filename(j, "mixed_mapping", filename);
				for (k = 0; k < file_page_nums[j]; k++) {
					ret = check_page_content(
						(void *)ptr,
						djb_hash(filename));
					ASSERT_EQ(ret, 0);
					ptr += PAGE_SIZE;
				}
			}
			exit(EXIT_SUCCESS);
		} else {
			int status;
			ASSERT_EQ(waitpid(pid, &status, 0), pid);
			ASSERT_TRUE(WIFEXITED(status));
			ASSERT_EQ(WEXITSTATUS(status), 0);
		}
	}
}

TEST_HARNESS_MAIN
