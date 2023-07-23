#define pr_fmt(fmt) "pseudo_mm:%s: " fmt, __func__

#include <asm/mmu_context.h>
#include <linux/hugetlb.h>
#include <linux/mempolicy.h>
#include <linux/mman.h>
#include <linux/rmap.h>
#include <linux/security.h>
#include <linux/userfaultfd_k.h>
#include <asm/cacheflush.h>
#include <linux/mm.h>
#include <linux/pseudo_mm.h>
#include <linux/slab.h>
#include <linux/xarray.h>
#include <linux/fs.h>
#include <linux/init.h>

#define stringify__(x) #x
#define stringify_(x) stringify__(x)
#define warn_weird_vma_flag(vma, pseudo_mm, flag_name)                  \
	pr_warn("Detect weird vma (#%lx - #%lx) with flag " stringify_( \
			flag_name) " in pseudo_mm %d !\n",              \
		vma->vm_start, vma->vm_end, pseudo_mm->id)

/* XArray used for id allocation */
DEFINE_XARRAY_ALLOC1(pseudo_mm_array);
/* kmemcache for pseudo_mm struct */
static struct kmem_cache *pseudo_mm_cachep;

#define pseudo_mm_alloc() (kmem_cache_alloc(pseudo_mm_cachep, GFP_KERNEL))

#define PSEUDO_MM_ID_MAX INT_MAX

/*
 * fill_page_from_file() - fill the content of the physical page from image file
 * @page: struct page of target
 * @file: image file
 * @offset: the offset to read data started from
 *
 * return 0 if success
 */
static unsigned long fill_page_from_file(struct page *page, struct file *file,
					 loff_t offset)
{
	void *buf;
	loff_t pos;
	ssize_t filled_size, wanted, ret;

	// TODO (huang-jl) deny_write_access ?
	buf = page_address(page);
	pos = offset;
	filled_size = 0;
	while (filled_size < PAGE_SIZE) {
		wanted = PAGE_SIZE - filled_size;
		ret = kernel_read(file, buf + filled_size, wanted, &pos);
		if (ret < 0) {
			pr_warn("fill a page (kernel_read) failed\n");
			return ret;
		}
		if (ret == 0)
			break;
		filled_size += ret;
	}
	if (filled_size != PAGE_SIZE) {
		pr_warn("fill a page with only %ld bytes\n", filled_size);
		return -EIO;
	}

	return 0;
}

int __init pseudo_mm_cache_init(void)
{
	pseudo_mm_cachep = KMEM_CACHE(pseudo_mm, SLAB_PANIC | SLAB_ACCOUNT);
	if (!pseudo_mm_cachep)
		return -ENOMEM;
	return 0;
}
postcore_initcall(pseudo_mm_cache_init);

/*
 * create a pseudo_mm struct and initialize it
 *
 * Return its id (> 0) when SUCCESS, return errno otherwise
 */
int create_pseudo_mm(void)
{
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

struct pseudo_mm *find_pseudo_mm(int id)
{
	struct pseudo_mm *pseudo_mm = NULL;
	unsigned long orig_id;

	// invalid id
	if (unlikely(id <= 0)) {
		pr_warn("find pseudo_mm with id = %d not exist\n", id);
		return NULL;
	}

	orig_id = id;
	pseudo_mm = xa_find(&pseudo_mm_array, &orig_id, orig_id, XA_PRESENT);
	BUG_ON(pseudo_mm && pseudo_mm->id != id);
	return pseudo_mm;
}

void delete_pseudo_mm(int id)
{
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
				     unsigned long flags)
{
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
	if (ret != start)
		pr_warn("Warning: add anonymous map to pseudo_mm at #%lx, but result at #%lx\n",
			start, ret);
	mmap_write_unlock(mm);
	// userfaultfd_unmap_complete(mm, &uf);
	if (!IS_ERR_VALUE(ret))
		ret = 0;

	return ret;
}

unsigned long pseudo_mm_fill_anon_map(int id, unsigned long start,
				      unsigned long size, struct file *image,
				      off_t offset)
{
	struct pseudo_mm *pseudo_mm;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	struct page **pages;
	unsigned long gup_flags, ret;
	int nr_pages, i;
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
	if (!vma || vma->vm_start != start || vma->vm_end != (start + size)) {
		pr_warn("fill area (#%lx - #%lx) does not match any vma\n",
			start, start + size);
		return -ENOENT;
	}

	if (!vma_is_anonymous(vma)) {
		pr_warn("vma at (#%lx - #%lx) is not anonymous\n", start,
			start + size);
		return -EINVAL;
	}

	nr_pages = size >> PAGE_SHIFT;
	// we are going to fill the content of this page
	gup_flags = FOLL_WRITE | FOLL_TOUCH | FOLL_FORCE;
	pages = kvmalloc_array(nr_pages, sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	nr_pin_pages =
		pin_user_pages_of(mm, start, nr_pages, gup_flags, pages, NULL);
	if (nr_pin_pages != nr_pages) {
		ret = -ENOMEM;
		goto pin_page_failed;
	}

	for (i = 0; i < nr_pages; i++) {
		ret = fill_page_from_file(pages[i], image,
					  offset + i * PAGE_SIZE);
		if (ret) {
			ret = -EIO;
			goto fill_page_failed;
		}
	}

	kvfree(pages);
	return 0;

pin_page_failed:
	if (nr_pin_pages > 0)
		unpin_user_pages(pages, nr_pin_pages);

fill_page_failed:
	kvfree(pages);
	return ret;
}

/*
 * pseudo_dup_mmap() - insert mmap from pseudo_mm into mm
 * @pseudo_mm: The source to insert from
 * @tsk: Owner of the @mm
 * @mm: The destination to insert into
 *
 * Similar to dup_mmap() which in kernel/fork.c, but we are doing insert not dup.
 * Some steps will be skipped, while some additional step will be added.
 */
static unsigned long pseudo_mm_attach_mmap(struct pseudo_mm *pseudo_mm,
					   struct task_struct *tsk,
					   struct mm_struct *mm)
{
	struct mm_struct *oldmm = pseudo_mm->mm;
	struct vm_area_struct *mpnt, *tmp;
	int retval;
	unsigned long charge = 0, tmp_vma_shared;
	LIST_HEAD(uf);
	MA_STATE(old_mas, &oldmm->mm_mt, 0, 0);
	MA_STATE(mas, &mm->mm_mt, 0, 0);

	uprobe_start_dup_mmap();
	if (mmap_write_lock_killable(oldmm)) {
		retval = -EINTR;
		goto fail_uprobe_end;
	}
	flush_cache_dup_mm(oldmm);
	uprobe_dup_mmap(oldmm, mm);
	/*
	 * Not linked in yet - no deadlock potential:
	 */
	mmap_write_lock_nested(mm, SINGLE_DEPTH_NESTING);

	// do not dup mm exe file

	mm->total_vm += oldmm->total_vm;
	mm->data_vm += oldmm->data_vm;
	mm->exec_vm += oldmm->exec_vm;
	mm->stack_vm += oldmm->stack_vm;

	// do not do ksm_fork or khugepaged_fork

	retval = mas_expected_entries(&mas, oldmm->map_count);
	if (retval)
		goto out;

	mas_for_each(&old_mas, mpnt, ULONG_MAX)
	{
		struct file *file;

		// This is roughly weird
		if (mpnt->vm_flags & VM_DONTCOPY) {
			warn_weird_vma_flag(mpnt, pseudo_mm, DONTCOPY);
			vm_stat_account(mm, mpnt->vm_flags, -vma_pages(mpnt));
			continue;
		}
		charge = 0;
		/*
		 * Don't duplicate many vmas if we've been oom-killed (for
		 * example)
		 */
		if (fatal_signal_pending(tsk)) {
			retval = -EINTR;
			goto loop_out;
		}
		if (mpnt->vm_flags & VM_ACCOUNT) {
			unsigned long len = vma_pages(mpnt);

			if (security_vm_enough_memory_mm(oldmm, len)) /* sic */
				goto fail_nomem;
			charge = len;
		}
		tmp = vm_area_dup(mpnt);
		if (!tmp)
			goto fail_nomem;
		retval = vma_dup_policy(mpnt, tmp);
		if (retval)
			goto fail_nomem_policy;
		tmp->vm_mm = mm;
		retval = dup_userfaultfd(tmp, &uf);
		if (retval)
			goto fail_nomem_anon_vma_fork;
		if (tmp->vm_flags & VM_WIPEONFORK) {
			/*
			 * VM_WIPEONFORK gets a clean slate in the child.
			 * Don't prepare anon_vma until fault since we don't
			 * copy page for current vma.
			 */
			warn_weird_vma_flag(tmp, pseudo_mm, WIPEONFORK);
			tmp->anon_vma = NULL;
		} else if (anon_vma_fork(tmp, mpnt))
			goto fail_nomem_anon_vma_fork;

		tmp->vm_flags &= ~(VM_LOCKED | VM_LOCKONFAULT);

		// TODO (huang-jl) check file-related logic
		file = tmp->vm_file;
		if (file) {
			struct address_space *mapping = file->f_mapping;

			get_file(file);
			i_mmap_lock_write(mapping);
			if (tmp->vm_flags & VM_SHARED)
				mapping_allow_writable(mapping);
			flush_dcache_mmap_lock(mapping);
			/* insert tmp into the share list, just after mpnt */
			vma_interval_tree_insert_after(tmp, mpnt,
						       &mapping->i_mmap);
			flush_dcache_mmap_unlock(mapping);
			i_mmap_unlock_write(mapping);
		}

		// Want to make sure that all pages are copy-on-write (specific for anonymous area),
		// so simply mark it PRIVATE here and restore after copy_page_range.
		if (vma_is_anonymous(tmp)) {
			tmp_vma_shared = tmp->vm_flags | VM_SHARED;
			tmp->vm_flags &= ~VM_SHARED;
		}
		/*
		 * TODO (huang-jl) Copy/update hugetlb private vma information.
		 */
		if (is_vm_hugetlb_page(tmp)) {
			warn_weird_vma_flag(tmp, pseudo_mm, HUGHTLB);
			hugetlb_dup_vma_private(tmp);
		}

		/* Link the vma into the MT */
		mas.index = tmp->vm_start;
		mas.last = tmp->vm_end - 1;
		mas_store(&mas, tmp);
		if (mas_is_err(&mas))
			goto fail_nomem_mas_store;

		mm->map_count++;
		if (!(tmp->vm_flags & VM_WIPEONFORK))
			retval = copy_page_range(tmp, mpnt);

		if (vma_is_anonymous(tmp) && tmp_vma_shared)
			tmp->vm_flags |= VM_SHARED;

		if (tmp->vm_ops && tmp->vm_ops->open)
			tmp->vm_ops->open(tmp);

		if (retval)
			goto loop_out;
	}
	/* a new mm has just been created */
	retval = arch_dup_mmap(oldmm, mm);
loop_out:
	mas_destroy(&mas);
out:
	mmap_write_unlock(mm);
	flush_tlb_mm(oldmm);
	mmap_write_unlock(oldmm);
	dup_userfaultfd_complete(&uf);
fail_uprobe_end:
	uprobe_end_dup_mmap();
	return retval;

fail_nomem_mas_store:
	unlink_anon_vmas(tmp);
fail_nomem_anon_vma_fork:
	mpol_put(vma_policy(tmp));
fail_nomem_policy:
	vm_area_free(tmp);
fail_nomem:
	retval = -ENOMEM;
	vm_unacct_memory(charge);
	goto loop_out;
}

unsigned long pseudo_mm_attach(pid_t pid, int id)
{
	struct task_struct *tsk;
	struct mm_struct *tsk_mm;
	struct pseudo_mm *pseudo_mm;
	unsigned long err;

	pseudo_mm = find_pseudo_mm(id);
	if (!pseudo_mm)
		return -ENOENT;

	rcu_read_lock();
	tsk = find_task_by_vpid(pid);
	if (!tsk) {
		pr_warn("cannot find task of pid %d\n", pid);
		return -ESRCH;
	}
	rcu_read_unlock();

	tsk_mm = get_task_mm(tsk);
	if (!tsk_mm) {
		// no mm_struct for task, do nothing
		pr_warn("cannot get tsk mm of pid %d!\n", pid);
		return 0;
	}

	err = pseudo_mm_attach_mmap(pseudo_mm, tsk, tsk_mm);
	if (err) {
		pr_warn("attach pseudo_mm (id = %d)'s mmap to pid %d failed!\n",
			id, pid);
		goto put_tsk_mm;
	}

put_tsk_mm:
	mmput(tsk_mm);

	return err ? err : 0;
}
