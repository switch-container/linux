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
	pgoff_t allocated_pg; /* number of page that has already been allocated */
	spinlock_t lock;
};

struct page *pseudo_mm_alloc_page(void);
pte_t pseudo_mm_page_to_pte(struct page *, struct vm_fault *);

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
 *
 * The meaning of params is the same as mmap()
 */
unsigned long pseudo_mm_add_map(int id, unsigned long start, unsigned long size,
				unsigned long prot, unsigned long flags, int fd,
				pgoff_t pgoff);

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

/* debug purpose */
void debug_weird_page(struct page *page, int expected_mapcount);

static inline bool vma_is_pseudo_mm_master(struct vm_area_struct *vma)
{
	return !!(vma->pseudo_mm_flag & PSEUDO_MM_VMA_MASTER);
}
#endif
