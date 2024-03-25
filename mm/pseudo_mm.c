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
#include <linux/shmem_fs.h>
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
static struct pseudo_mm_backend backend;
static pseudo_mm_rdma_pf_ops_t *pseudo_mm_rdma_pf_ops = NULL;

#define pseudo_mm_alloc() (kmem_cache_alloc(pseudo_mm_cachep, GFP_KERNEL))

#define PSEUDO_MM_ID_MAX INT_MAX

#ifdef PSEUDO_MM_DEBUG
static bool __maybe_unused show_rmap_vma(struct folio *folio,
					 struct vm_area_struct *vma,
					 unsigned long address, void *arg)
{
	pr_info("\tweird page %p (mapcount %d) found in vma %p at address #%lx\n",
		&folio->page, folio_mapcount(folio), vma, address);
	return true;
}

void __maybe_unused debug_weird_page(struct page *page, int expected_mapcount)
{
	struct folio *folio = page_folio(page);
	int we_locked = 0;
	struct rmap_walk_control rwc = {
		.rmap_one = show_rmap_vma,
		.arg = NULL,
	};

	if (folio_mapcount(folio) == expected_mapcount)
		return;

	if (!folio_test_locked(folio)) {
		we_locked = 1;
		folio_lock(folio);
	}
	rmap_walk(folio, &rwc);
	if (we_locked)
		folio_unlock(folio);
}
#else
void __maybe_unused debug_weird_page(struct page *page, int expected_mapcount)
{
}
#endif

int __init pseudo_mm_cache_init(void)
{
	pseudo_mm_cachep = KMEM_CACHE(pseudo_mm, SLAB_PANIC | SLAB_ACCOUNT);
	if (!pseudo_mm_cachep)
		return -ENOMEM;
	return 0;
}
postcore_initcall(pseudo_mm_cache_init);

unsigned long register_pseudo_mm_rdma_pf_handler(pseudo_mm_rdma_pf_ops_t *op)
{
	if (pseudo_mm_rdma_pf_ops != NULL) {
		pr_err("only allowed to register one pseudo_mm_rdma_pf_handler, already set to %p!",
		       pseudo_mm_rdma_pf_ops);
		return -EEXIST;
	}
	pseudo_mm_rdma_pf_ops = op;
	return 0;
}
EXPORT_SYMBOL(register_pseudo_mm_rdma_pf_handler);

int pseudo_mm_rdma_pf_handle(struct page *page, pgoff_t remote_pgoff)
{
	if (pseudo_mm_rdma_pf_ops)
		return pseudo_mm_rdma_pf_ops(page, remote_pgoff);
	return -ENOENT;
}

unsigned long register_backend_dax_device(int fd)
{
	struct file *backend_file;
	unsigned long ret;

	// if (backend.filp)
	// return -EEXIST;
	// For now, the backend do not keep state across
	// different request of setup page table, so I allow to register
	// multiple times for flexibility.
	if (backend.filp) {
		fput(backend.filp);
		pr_warn("pseudo_mm backend dax device has changed\n");
		backend.filp = NULL;
	}

	backend_file = fget(fd);
	if (!backend_file)
		return -EBADF;
	if (!IS_DAX(backend_file->f_mapping->host)) {
		ret = -EBADF;
		goto err;
	}
	backend.filp = backend_file;

	return 0;
err:
	fput(backend_file);
	return ret;
}

inline bool pseudo_mm_rdma_pf_handler_enable(void)
{
	return pseudo_mm_rdma_pf_ops != NULL;
}

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
	INIT_LIST_HEAD(&pseudo_mm->pages_list);

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
		pr_warn("process %d find pseudo_mm with invalid id = %d\n",
			current->pid, id);
		return NULL;
	}

	orig_id = id;
	pseudo_mm = xa_find(&pseudo_mm_array, &orig_id, orig_id, XA_PRESENT);
	WARN_ON(pseudo_mm && pseudo_mm->id != id);
	return pseudo_mm;
}

static void put_pseudo_mm(struct pseudo_mm *pseudo_mm)
{
	struct pseudo_mm_pin_pages *pin_page, *tmp;
	list_for_each_entry_safe(pin_page, tmp, &pseudo_mm->pages_list, list) {
		list_del(&pin_page->list);
		unpin_user_pages(pin_page->pages, pin_page->nr_pin_pages);
		kvfree(pin_page->pages);
		kfree(pin_page);
	}
	if (pseudo_mm->mm)
		mmput(pseudo_mm->mm);
	if (pseudo_mm->id > 0)
		xa_erase(&pseudo_mm_array, pseudo_mm->id);
	kmem_cache_free(pseudo_mm_cachep, pseudo_mm);
}

void put_pseudo_mm_with_id(int id)
{
	struct pseudo_mm *pseudo_mm;
	pr_info("process %d put pseudo_mm id %d\n", current->pid, id);
	// id == -1 is a specical case to delete all pseudo_mm
	if (id == -1) {
		unsigned long idx;
		xa_for_each(&pseudo_mm_array, idx, pseudo_mm) {
			if (pseudo_mm)
				put_pseudo_mm(pseudo_mm);
		}
		return;
	}

	pseudo_mm = find_pseudo_mm(id);
	if (pseudo_mm)
		put_pseudo_mm(pseudo_mm);
}

unsigned long pseudo_mm_add_map(int id, unsigned long start, unsigned long size,
				unsigned long prot, unsigned long flags, int fd,
				pgoff_t pgoff)
{
	struct pseudo_mm *pseudo_mm;
	struct mm_struct *mm;
	struct file *file = NULL;
	unsigned long ret;

	// we only accept PageAligned address and size
	if (!PAGE_ALIGNED(start) || !PAGE_ALIGNED(size) || size == 0) {
		return -EINVAL;
	}
	// do not support huge tlb now
	if (flags & MAP_HUGETLB)
		return -EINVAL;

	if ((flags & (MAP_ANONYMOUS | MAP_SHARED)) ==
	    (MAP_ANONYMOUS | MAP_SHARED)) {
		pr_warn("do not support anonymous shared mapping!\n");
		return -EINVAL;
	}

	if ((flags & MAP_ANONYMOUS) && fd != -1)
		return -EINVAL;

	if (!(flags & MAP_ANONYMOUS)) {
		file = fget(fd);
		if (!file)
			return -EBADF;
	}

	pseudo_mm = find_pseudo_mm(id);
	if (!pseudo_mm) {
		ret = -ENOENT;
		goto out;
	}
	mm = pseudo_mm->mm;

	if (mmap_write_lock_killable(mm)) {
		ret = -EINTR;
		goto out;
	}
	// we skip userfaultfd here
	ret = do_mmap_to(mm, file, start, size, prot, flags, pgoff, NULL);
	if (ret != start)
		pr_warn("Warning: add anonymous map to pseudo_mm at #%lx, but result at #%lx\n",
			start, ret);
	mmap_write_unlock(mm);
	// userfaultfd_unmap_complete(mm, &uf);
	if (!IS_ERR_VALUE(ret))
		ret = 0;
out:
	if (file)
		fput(file);
	return ret;
}

/*
 * pseudo_dup_mmap() - insert mmap from pseudo_mm into mm
 * @id: id of pseudo_mm
 * @pseudo_mm: The source to insert from
 * @tsk: Owner of the @mm
 * @mm: The destination to insert into
 *
 * Similar to dup_mmap() which in kernel/fork.c, but we are doing insert not dup.
 * Some steps will be skipped, while some additional step will be added.
 */
static unsigned long pseudo_mm_attach_mmap(int id, struct pseudo_mm *pseudo_mm,
					   struct task_struct *tsk,
					   struct mm_struct *mm)
{
	struct mm_struct *oldmm = pseudo_mm->mm;
	struct vm_area_struct *mpnt, *tmp;
	int retval = 0;
	unsigned long addr;
	unsigned long charge = 0, tmp_vm_flags;
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
		// newly created vma should not be master
		tmp->pseudo_mm_flag &= ~PSEUDO_MM_VMA_MASTER;
		// we try to setup a new zero shmem file in page_fault_handler
		if (vma_is_pseudo_anon_shared(mpnt)) {
			// tmp->pseudo_mm_flag |= id;
			// setup a new sheme zero file when attach
			// pr_info("pseudo_mm create new vma %p old vm_file's mapping = #%p",
			// 	tmp, tmp->vm_file->f_mapping);
			pr_warn("pseudo_mm create anon shared vma which is not well supported\n");
			tmp->vm_file = NULL;
			retval = shmem_zero_setup(tmp);
			if (retval)
				goto fail_with_retval;
			file = tmp->vm_file;
			BUG_ON(!file);

			i_mmap_lock_write(file->f_mapping);
			mapping_allow_writable(file->f_mapping);
			flush_dcache_mmap_lock(file->f_mapping);
			vma_interval_tree_insert(tmp, &file->f_mapping->i_mmap);
			flush_dcache_mmap_unlock(file->f_mapping);
			i_mmap_unlock_write(file->f_mapping);
			mapping_unmap_writable(file->f_mapping);
			/* TODO (huang-jl) is this needed ? */
			// uprobe_mmap(tmp);
			goto skip_normal_file;
		}

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

skip_normal_file:
		// TODO (huang-jl) how about file-backed mapping ?
		// Want to make sure that all pages are copy-on-write,
		// so simply mark it PRIVATE here and restore after copy_page_range().
		// The pte will be write-protected.
		if (vma_is_pseudo_anon_shared(mpnt)) {
			WARN(tmp->vm_flags != mpnt->vm_flags,
			     "tmp and mpnt flag corrupt: %lx vs %lx\n",
			     tmp->vm_flags, mpnt->vm_flags);
			tmp_vm_flags = tmp->vm_flags;
			tmp->vm_flags &= ~VM_SHARED;
			mpnt->vm_flags &= ~VM_SHARED;
		}
		/*
		 * TODO (huang-jl) Copy/update hugetlb private vma information.
		 */
		if (is_vm_hugetlb_page(tmp)) {
			warn_weird_vma_flag(tmp, pseudo_mm, HUGHTLB);
			hugetlb_dup_vma_private(tmp);
		}

		/* Link the vma into the MT, and
		 * make sure that there is **no overlapping**.
		 */
		mas_set_range(&mas, tmp->vm_start, tmp->vm_end - 1);
		mas_insert(&mas, tmp);
		if (mas_is_err(&mas)) {
			retval = xa_err(mas.node);
			goto fail_with_retval;
		}

		// mas.index = tmp->vm_start;
		// mas.last = tmp->vm_end - 1;
		// mas_store(&mas, tmp);
		// if (mas_is_err(&mas))
		// 	goto fail_nomem_mas_store;

		mm->map_count++;

		if (!(tmp->vm_flags & VM_WIPEONFORK))
			retval = copy_page_range(tmp, mpnt);

#ifdef PSEUDO_MM_DEBUG
		// Debug: check for page table entry
		if (vma_is_pseudo_anon_shared(tmp)) {
			addr = tmp->vm_start;
			while (addr < tmp->vm_end) {
				pgd_t *pgd = pgd_offset(mm, addr);
				WARN(pgd_none(*pgd), "va #%lx pgd is none",
				     addr);
				p4d_t *p4d = p4d_offset(pgd, addr);
				WARN(p4d_none(*p4d), "va #%lx p4d is none",
				     addr);
				pud_t *pud = pud_offset(p4d, addr);
				WARN(pud_none(*pud), "va #%lx pud is none",
				     addr);
				pmd_t *pmd = pmd_offset(pud, addr);
				WARN(pmd_none(*pmd), "va #%lx pmd is none",
				     addr);
				pte_t *pte = pte_offset_kernel(pmd, addr);
				WARN(pte_none(*pte), "va #%lx pte is none",
				     addr);
				WARN(pte_write(*pte), "va #%lx pte is writable",
				     addr);
				addr += PAGE_SIZE;
			}
		}
#endif

		if (vma_is_pseudo_anon_shared(mpnt)) {
			tmp->vm_flags = tmp_vm_flags;
			mpnt->vm_flags = tmp_vm_flags;
		}

		if (tmp->vm_ops && tmp->vm_ops->open)
			tmp->vm_ops->open(tmp);

		if (retval)
			goto loop_out;
	}
	/* a new mm has just been created */
	// retval = arch_dup_mmap(oldmm, mm);
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

fail_nomem_anon_vma_fork:
	mpol_put(vma_policy(tmp));
fail_nomem_policy:
	vm_area_free(tmp);
fail_nomem:
	retval = -ENOMEM;
	vm_unacct_memory(charge);
	goto loop_out;

fail_with_retval:
	unlink_anon_vmas(tmp);
	mpol_put(vma_policy(tmp));
	vm_area_free(tmp);
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
	if (!pseudo_mm) {
		pr_warn("cannot find pseudo_mm with id %d\n", id);
		return -ENOENT;
	}

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

	err = pseudo_mm_attach_mmap(id, pseudo_mm, tsk, tsk_mm);
	if (err)
		pr_warn("attach pseudo_mm (id = %d)'s mmap to pid %d failed!\n",
			id, pid);

	mmput(tsk_mm);

	return err ? err : 0;
}

bool vma_is_pseudo_anon_shared(struct vm_area_struct *vma)
{
	return !!(vma->pseudo_mm_flag & PSEUDO_MM_VMA_ANON_SHARED);
}

inline struct pseudo_mm_backend *pseudo_mm_get_backend(void)
{
	return &backend;
}
