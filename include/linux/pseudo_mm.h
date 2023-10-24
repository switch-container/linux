#ifndef __LINUX_PSEUDO_MM__
#define __LINUX_PSEUDO_MM__

#include <linux/mm_types.h>
#include <linux/xarray.h>
#include <linux/rmap.h>

#define PSEUDO_MM_DEBUG

struct pseudo_mm {
	struct mm_struct *mm;
	int id;
	/* list of pseudo_mm_pin_pages */
	struct list_head pages_list;
};

struct pseudo_mm_pin_pages {
	struct list_head list;
	long nr_pin_pages;
	struct page **pages;
};

struct pseudo_mm_unmap_args {
	enum ttu_flags flags;
	struct vm_area_struct *curr;
	pte_t orig_pte;
	struct folio *old_folio;
};

struct pseudo_mm_backend {
	struct file *filp;
};

/* return 0 if succeed */
unsigned long register_backend_dax_device(int fd);
inline struct pseudo_mm_backend *pseudo_mm_get_backend(void);

/*
 * create_pseudo_mm() - create and init the pseudo_mm
 *
 * return the id of that pseudo_mm, which can be used to find_pseudo_mm()
 */
int create_pseudo_mm(void);
struct pseudo_mm *find_pseudo_mm(int id);

/*
 * put_pseudo_mm_with_id() - delete the pseudo_mm corresponding to id
 * @id: the id of the pseudo_mm that needed to be deleted, -1 to delete
 * all pseudo_mm
 */
void put_pseudo_mm_with_id(int id);
/*
 * Add a memory mapping to this pseudo_mm.
 * This will not fill content of the physical page.
 * Support file-backed mapping and anonymous private mapping.
 * (Do not support anonymous shared mapping for now.)
 *
 * The meaning of params is the same as mmap()
 */
unsigned long pseudo_mm_add_map(int id, unsigned long start, unsigned long size,
				unsigned long prot, unsigned long flags, int fd,
				pgoff_t pgoff);

/*
 * pseudo_mm_setup_pt() - setup page table of pseudo_mm's virtual address
 * @id: pseudo_mm id
 * @start: start address
 * @size: size of continuous virtual address
 * @pgoff: physical page offset of backend dax device (page number)
 *
 * This function will establish the page table of virtual address range
 * [start, start + size) and let it point to physical page start at pgoff
 * in backend dax device (the page table is read-only).
 *
 * *Note*: The [start, start + size) should not exceed the boundary of single
 * vma. Return 0 when succeed.
 */
unsigned long pseudo_mm_setup_pt(int id, unsigned long start,
				 unsigned long size, pgoff_t pgoff);

/*
 * pseudo_mm_bring_back() - bring the virtual memory in pseudo_mm back to local memory.
 * @id: pseudo_mm id
 * @start: start address
 * @size: size of continuous virtual address
 *
 * This function will bring the memory of virtual address range
 * [start, start + size) back to local memory. 
 *
 * *Note*: The [start, start + size) should not exceed the boundary of single
 * vma. Return 0 when succeed.
 */
unsigned long pseudo_mm_bring_back(int id, unsigned long start,
				   unsigned long size);

/*
 * pseudo_mm_attach() - insert *all* memory mapping into an existing process's address space
 * @pid: process id
 * @id: pseudo_mm_id
 */
unsigned long pseudo_mm_attach(pid_t pid, int id);

/* debug purpose */
void debug_weird_page(struct page *page, int expected_mapcount);

static inline bool vma_is_pseudo_mm_master(struct vm_area_struct *vma)
{
	return (vma->pseudo_mm_flag & (PSEUDO_MM_VMA_MASTER | PSEUDO_MM_VMA)) ==
	       (PSEUDO_MM_VMA_MASTER | PSEUDO_MM_VMA);
}

static inline bool vma_is_pseudo_mm(struct vm_area_struct *vma)
{
	return !!(vma->pseudo_mm_flag & PSEUDO_MM_VMA);
}

#endif
