#ifndef __LINUX_PSEUDO_MM__
#define __LINUX_PSEUDO_MM__

#include <linux/mm_types.h>
#include <linux/xarray.h>

struct pseudo_mm {
	struct mm_struct *mm;
	int id;
	// refcount used to prevent anonymous shared memory from delete
	refcount_t ref;
};

/*
 * create_pseudo_mm() - create and init the pseudo_mm
 *
 * return the id of that pseudo_mm, which can be used to find_pseudo_mm()
 */
int create_pseudo_mm(void);
struct pseudo_mm *find_pseudo_mm(int id);
void put_pseudo_mm_with_id(int id);
/*
 * Add an anonymous memory mapping to this pseudo_mm.
 * This will not fill content of the physical page
 *
 * The meaning of params is the same as mmap()
 */
unsigned long pseudo_mm_add_anon_map(int id, unsigned long start,
				     unsigned long size, unsigned long prot,
				     unsigned long flags);

/*
 * pseudo_mm_fill_anon_map() - Fill the memory content of the vma
 * @id: id of the target pseudo_mm
 * @start: start address of the anon vma
 * @size: length of the anon vma
 * @content: the memory image file
 * @offset: offset within the image file corresponding to the vma (start at
 * @start)
 */
unsigned long pseudo_mm_fill_anon_map(int id, unsigned long start,
				      unsigned long size, struct file *content,
				      off_t offset);

/*
 * Add an file-backed memory mapping to this pseudo_mm.
 * TODO (huang-jl): how to design an API, what arguments this method need?
 */
unsigned long pseudo_mm_add_file_map(int id, unsigned long start,
				     unsigned long size);

/*
 * pseudo_mm_attach() - insert *all* memory mapping into an existing process's address space
 * @pid: process id
 * @id: pseudo_mm_id
 */
unsigned long pseudo_mm_attach(pid_t pid, int id);
#endif
