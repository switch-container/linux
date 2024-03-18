// SPDX-License-Identifier: GPL-2.0-only
/*
 * This module provides the feature to manage memory on the dax devcie
 */
#define pr_fmt(fmt) "pseudo_mm_memory:%s: " fmt, __func__

#include <linux/file.h>
#include <linux/dax.h>
#include <linux/pfn_t.h>
#include <linux/spinlock.h>
#include <linux/pseudo_mm.h>
#include <linux/mm.h>

#include "../bus.h"
#include "../dax-private.h"
#include "pseudo_mm_memory.h"

/* 
 * setup read-only page table entry for vma in pseudo_mm
 * @start: start virtual address
 * @nr_pages: number of pages needed to be set
 * @pgoff: page offset of dax device
 */
static unsigned long __setup_pt_for_vma_dax(struct pseudo_mm *pseudo_mm,
					    struct vm_area_struct *vma,
					    unsigned long start,
					    unsigned long nr_pages,
					    pgoff_t pgoff)
{
	struct pseudo_mm_backend *backend = pseudo_mm_get_backend();
	struct dev_dax *dev_dax;
	struct pseudo_mm_pin_pages *pin_page = NULL;
	struct dev_pagemap *pgmap = NULL;
	struct page *page, **pages;
	phys_addr_t phys;
	int id;
	pfn_t pfn;
	unsigned long ret = 0, i, vaddr;
	long nr_pin_pages = 0;
	vm_fault_t vmf_ret;

	if (!backend->filp) {
		pr_err("do not register dax backend for pseudo_mm\n");
		return -ENOENT;
	}

	dev_dax = backend->filp->private_data;

	pages = kvmalloc_array(nr_pages, sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	id = dax_read_lock();
	if (dev_dax->align != PAGE_SIZE) {
		pr_warn("dax alignment (%#x) != PAGE_SIZE\n", dev_dax->align);
		ret = -EIO;
		goto failed;
	}

	// Map pages to dax device one by one
	// since insert_mixed api is insert one pfn at a time.
	// However, its performance not a big deal, since __setup_pt_for_vma is
	// called on prepare phase, it will not effect the attach performance.
	for (i = 0; i < nr_pages; i++) {
		vaddr = start + (i << PAGE_SHIFT);
		phys = dax_pgoff_to_phys(dev_dax, pgoff + i, PAGE_SIZE);
		if (phys == -1) {
			pr_warn("pgoff_to_phys(%ld) failed\n", pgoff + i);
			ret = -EFAULT;
			goto failed;
		}
		pfn = phys_to_pfn_t(phys, PFN_DEV | PFN_MAP);

		vmf_ret = pseudo_mm_insert_dax(vma, vaddr, pfn);
		if (unlikely(vmf_ret & VM_FAULT_ERROR)) {
			pr_warn("pseudo_mm_insert_dax vaddr %#lx pfn %#llx phys %#llx failed\n",
				vaddr, pfn.val, phys);
			ret = -EFAULT;
			goto failed;
		}
		// BEGIN imitate pin_user_pages()
		pgmap = get_dev_pagemap(pfn_t_to_pfn(pfn), pgmap);
		WARN_ON(!pgmap);
		page = pfn_t_to_page(pfn);
		if (unlikely(!try_grab_page(page, FOLL_PIN))) {
			ret = -ENOMEM;
			goto failed;
		}
		ret = arch_make_page_accessible(page);
		if (ret) {
			unpin_user_page(page);
			goto failed;
		}
		pages[nr_pin_pages++] = page;
		flush_anon_page(vma, page, start);
		flush_dcache_page(page);
		// END imitate pin_user_pages()
	}

	pin_page = kmalloc(sizeof(*pin_page), GFP_KERNEL);
	if (!pin_page) {
		ret = -ENOMEM;
		goto failed;
	}

	BUG_ON(nr_pin_pages != nr_pages);
	INIT_LIST_HEAD(&pin_page->list);
	pin_page->pages = pages;
	pin_page->nr_pin_pages = nr_pin_pages;
	list_add(&pin_page->list, &pseudo_mm->pages_list);

#ifdef PSEUDO_MM_DEBUG
	pr_info("setup page table %#lx - %#lx (V) to DAX pgoff %#lx - %#lx\n",
		start, start + (nr_pages << PAGE_SHIFT), pgoff,
		pgoff + nr_pages);
#endif

out:
	if (pgmap)
		put_dev_pagemap(pgmap);
	dax_read_unlock(id);
	return ret;

failed:
	if (nr_pin_pages > 0)
		unpin_user_pages(pages, nr_pin_pages);
	kvfree(pages);
	if (pin_page)
		kfree(pin_page);
	goto out;
}

/* 
 * setup rdma page table entry for vma in pseudo_mm
 * @start: start virtual address
 * @nr_pages: number of pages needed to be set
 * @pgoff: page offset of dax device
 */
static unsigned long __setup_pt_for_vma_rdma(struct pseudo_mm *pseudo_mm,
					     struct vm_area_struct *vma,
					     unsigned long start,
					     unsigned long nr_pages,
					     pgoff_t pgoff)
{
	unsigned long ret = 0, i, vaddr;
	vm_fault_t vmf_ret;

	if (!pseudo_mm_rdma_pf_handler_enable()) {
		pr_err("pseudo_mm_rdma_pf_handler not enable\n");
		return -ENOENT;
	}

	// Map pages to dax device one by one
	// since insert_mixed api is insert one pfn at a time.
	// However, its performance not a big deal, since __setup_pt_for_vma is
	// called on prepare phase, it will not effect the attach performance.
	for (i = 0; i < nr_pages; i++) {
		vaddr = start + (i << PAGE_SHIFT);
		vmf_ret = pseudo_mm_insert_rdma(vma, vaddr, pgoff + i);
		if (unlikely(vmf_ret & VM_FAULT_ERROR)) {
			pr_warn("pseudo_mm_insert_rdma vaddr %#lx pgoff %#lx failed\n",
				vaddr, pgoff + i);
			ret = -EFAULT;
			goto out;
		}
	}

#ifdef PSEUDO_MM_DEBUG
	pr_info("setup page table %#lx - %#lx (V) to RDMA pgoff %#lx - %#lx\n",
		start, start + (nr_pages << PAGE_SHIFT), pgoff,
		pgoff + nr_pages);
#endif

out:
	return ret;
}

unsigned long pseudo_mm_setup_pt(int id, unsigned long start,
				 unsigned long size, pgoff_t pgoff,
				 enum pseudo_mm_pt_type type)
{
	struct pseudo_mm *pseudo_mm = find_pseudo_mm(id);
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	unsigned long end = start + size;
	unsigned long ret;

	if (!pseudo_mm)
		return -ENOENT;
	mm = pseudo_mm->mm;
	mmap_read_lock_killable(mm); // find_vma_intersection() need mmap lock
	vma = find_vma_intersection(mm, start, end);
	if (!range_in_vma(vma, start, end)) {
		pr_warn("(%#lx - %#lx) is not within single vma\n", start, end);
		ret = -EFAULT;
		goto out;
	}
	if (!vma_is_pseudo_mm_master(vma)) {
		pr_warn("vma (%#lx - %#lx) is not pseudo mm master\n",
			vma->vm_start, vma->vm_end);
		ret = -EINVAL;
		goto out;
	}

	// Couple of things that happened in normal anon private page fault handler:
	// 1. prepare_anon_vma
	// 2. add page to anon_vma and lru list
	// we need to do 1 (so that copy_page_range will copy page table) but do not need to do 2:
	// since these pages are used exclusively by pseudo_mm module
	if (unlikely(anon_vma_prepare(vma))) {
		ret = -ENOMEM;
		goto out;
	}

	switch (type) {
	case DAX_MEM:
		ret = __setup_pt_for_vma_dax(pseudo_mm, vma, start,
					     size >> PAGE_SHIFT, pgoff);
		break;
	case RDMA_MEM:
		ret = __setup_pt_for_vma_rdma(pseudo_mm, vma, start,
					      size >> PAGE_SHIFT, pgoff);
		break;
	default:
		ret = -EINVAL;
	}
out:
	mmap_read_unlock(mm);
	return ret;
}

unsigned long pseudo_mm_bring_back(int id, unsigned long start,
				   unsigned long size)
{
	struct pseudo_mm *pseudo_mm;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	unsigned long vaddr, end = start + size;
	unsigned long ret;

	// start and size must be page aligned
	if (!PAGE_ALIGNED(start) || !PAGE_ALIGNED(size) || size == 0)
		return -EINVAL;
	pseudo_mm = find_pseudo_mm(id);
	if (!pseudo_mm)
		return -ENOENT;

	mm = pseudo_mm->mm;
	mmap_read_lock_killable(mm); // find_vma_intersection() need mmap lock
	vma = find_vma_intersection(mm, start, end);
	if (!range_in_vma(vma, start, end)) {
		pr_warn("(%#lx - %#lx) is not within single vma\n", start, end);
		ret = -EFAULT;
		goto out;
	}
	if (!vma_is_pseudo_mm_master(vma)) {
		pr_warn("vma (%#lx - %#lx) is not pseudo mm master\n",
			vma->vm_start, vma->vm_end);
		ret = -EINVAL;
		goto out;
	}
	// TODO(huang-jl): I only support to bring back private anonymous vma for now.
	// For shared anonymous area: it is really hard to implement a mm template (more info
	// can be found at pseudo_mm branch and git commit message).
	// For file-backed area: it is already backed by page-cache (or local memory) by default.
	//
	// In fact this is not a todo, I just do not want to implement for shared anonymous vma :(
	if (!vma_is_anonymous(vma) || (vma->vm_flags & VM_SHARED)) {
		pr_warn("try to bring back memory within vma (%#lx - %#lx), which is not anonymous private vma\n",
			vma->vm_start, vma->vm_end);
		ret = -EINVAL;
		goto out;
	}

	// bring back pages one by one
	for (vaddr = start; vaddr < end; vaddr += PAGE_SIZE) {
		ret = pseudo_mm_bring_back_single_page(mm, vma, vaddr);
		if (ret) {
			goto out;
		}
	}
out:
	mmap_read_unlock(mm);
	return ret;
}
