#include "asm-generic/bug.h"
#include <linux/mm.h>
#include <linux/pseudo_mm.h>
#include <linux/slab.h>
#include <linux/xarray.h>

/* XArray used for id allocation */
DEFINE_XARRAY_ALLOC1(pseudo_mm_array);

/* kmemcache for pseudo_mm struct */
static struct kmem_cache *pseudo_mm_cachep;

#define pseudo_mm_alloc() (kmem_cache_alloc(pseudo_mm_cachep, GFP_KERNEL))

#define PSEUDO_MM_ID_MAX INT_MAX

// TODO: call init function
void __init pseudo_mm_cache_init(void) {
  pseudo_mm_cachep = KMEM_CACHE(pseudo_mm, SLAB_PANIC | SLAB_ACCOUNT);
}

/*
 * create a pseudo_mm struct and initialize it
 *
 * Return its id (> 0) when SUCCESS, return errno otherwise
 */
int create_pseudo_mm(void) {
  struct mm_struct *mm;
  struct pseudo_mm *pseudo_mm;
  struct xa_limit limit;
  int ret, id;

  mm = mm_alloc_wo_task();
  if (!mm)
    return -ENOMEM;

  pseudo_mm = pseudo_mm_alloc();
  if (!pseudo_mm) {
    ret = -ENOMEM;
    goto drop_mm;
  }
  pseudo_mm->mm = mm;

  // insert newly created pseudo into xarray
  limit = XA_LIMIT(1, PSEUDO_MM_ID_MAX);
  ret = xa_alloc(&pseudo_mm_array, &id, pseudo_mm, limit, GFP_KERNEL);
  if (ret < 0)
    goto drop_pseudo_mm;

  pseudo_mm->id = id;
  return id;

drop_pseudo_mm:
  kmem_cache_free(pseudo_mm_cachep, pseudo_mm);
drop_mm:
  mmdrop(mm);
  return ret;
}

struct pseudo_mm *find_pseudo_mm(int id) {
  struct pseudo_mm *pseudo_mm = NULL;
  unsigned long orig_id;

  // invalid id
  if (unlikely(id <= 0))
    return NULL;

  orig_id = id;
  pseudo_mm = xa_find(&pseudo_mm_array, &orig_id, orig_id, XA_PRESENT);
  BUG_ON(pseudo_mm && pseudo_mm->id != id);
  return pseudo_mm;
}

void delete_pseudo_mm(int id) {
  struct pseudo_mm *pseudo_mm;
  pseudo_mm = find_pseudo_mm(id);
  if (!pseudo_mm)
    return;

  if (pseudo_mm->mm)
    mmput(pseudo_mm->mm);
  if (pseudo_mm->id > 0)
    xa_erase(&pseudo_mm_array, pseudo_mm->id);

  kmem_cache_free(pseudo_mm_cachep, pseudo_mm);
}

unsigned long pseudo_mm_add_anon_map(int id, unsigned long start,
                                     unsigned long size, unsigned long prot,
                                     unsigned long flags) {
  struct pseudo_mm *pseudo_mm;
  struct mm_struct *mm;
  unsigned long ret;

  // we only accept PageAligned address and size
  if (!PAGE_ALIGNED(start) || !PAGE_ALIGNED(size) || size == 0) {
    return -EINVAL;
  }
  pseudo_mm = find_pseudo_mm(id);
  if (!pseudo_mm)
    return -ENOENT;
  mm = pseudo_mm->mm;

  if (mmap_write_lock_killable(mm))
    return -EINTR;
  // we skip userfaultfd here
  ret = do_mmap_to(mm, NULL, start, size, prot, flags, 0, NULL);
  WARN(ret != start,
       "Warning: add anonymous map to pseudo_mm at #%lx, but result at #%lx",
       start, ret);
  mmap_write_unlock(mm);
  // userfaultfd_unmap_complete(mm, &uf);
  if (!IS_ERR_VALUE(ret))
    ret = 0;

  return ret;
}

unsigned long pseudo_mm_fill_anon_map(int id, unsigned long start,
                                      unsigned long size, struct file *content,
                                      unsigned long offset) {
  struct pseudo_mm *pseudo_mm;
  struct mm_struct *mm;
  struct vm_area_struct *vma;
  struct page** pages;
  unsigned long gup_flags;
  int nr_pages;
  long nr_pin_pages;

  // we only accept PageAligned address and size
  if (!PAGE_ALIGNED(start) || !PAGE_ALIGNED(size) || size == 0) {
    return -EINVAL;
  }
  pseudo_mm = find_pseudo_mm(id);
  if (!pseudo_mm)
    return -ENOENT;
  mm = pseudo_mm->mm;
  vma = find_vma(mm, start);
  if (!vma || vma->vm_start != start || vma->vm_end != (start + size))
    return -ENOENT;

  nr_pages = size >> PAGE_SHIFT;
  // we are going to fill the content of this page
  gup_flags = FOLL_WRITE | FOLL_TOUCH | FOLL_FORCE;
  pages = kvmalloc_array(nr_pages, sizeof(struct page*), GFP_KERNEL);
  if (!pages)
    return -ENOMEM;

  nr_pin_pages = pin_user_pages_of(mm, start, nr_pages, gup_flags, pages, NULL);
  if (nr_pin_pages != nr_pages)
    goto pin_page_failed;
  // TODO write content to pages


pin_page_failed:
  if (nr_pin_pages > 0)
    unpin_user_pages(pages, nr_pin_pages);

  kvfree(pages);
  return -ENOMEM;
}
