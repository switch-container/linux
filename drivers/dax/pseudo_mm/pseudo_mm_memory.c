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
static unsigned long __setup_pt_for_vma(struct pseudo_mm *pseudo_mm,
					struct vm_area_struct *vma,
					unsigned long start,
					unsigned long nr_pages, pgoff_t pgoff)
{
	struct pseudo_mm_backend *backend = pseudo_mm_get_backend();
	struct dev_dax *dev_dax = backend->filp->private_data;
	struct pseudo_mm_pin_pages *pin_page = NULL;
	struct dev_pagemap *pgmap = NULL;
	struct page *page, **pages;
	phys_addr_t phys;
	int id;
	pfn_t pfn;
	unsigned long ret = 0, i, vaddr;
	long nr_pin_pages = 0;
	vm_fault_t vmf_ret;

	pages = kvmalloc_array(nr_pages, sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	id = dax_read_lock();
	if (dev_dax->align != PAGE_SIZE) {
		pr_warn("alignment (%#x) != PAGE_SIZE\n", dev_dax->align);
		ret = -EIO;
		goto failed;
	}

	// map pages one by one
	for (i = 0; i < nr_pages; i++) {
		vaddr = start + (i << PAGE_SHIFT);
		phys = dax_pgoff_to_phys(dev_dax, pgoff + i, PAGE_SIZE);
		if (phys == -1) {
			pr_warn("pgoff_to_phys(%ld) failed\n", pgoff + i);
			ret = -EFAULT;
			goto failed;
		}
		pfn = phys_to_pfn_t(phys, PFN_DEV | PFN_MAP);

		vmf_ret = pseudo_mm_insert_mixed(vma, vaddr, pfn);
		if (unlikely(vmf_ret & VM_FAULT_ERROR)) {
			pr_warn("vmf_insert_mixed vaddr %#lx pfn %#llx phys %#llx failed\n",
				vaddr, pfn.val, phys);
			ret = -EFAULT;
			goto failed;
		}
#ifdef PSEUDO_MM_DEBUG
		pr_info("setup page table %#lx (V) to %#llx (P)\n", vaddr,
			phys);
#endif
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

unsigned long pseudo_mm_setup_pt(int id, unsigned long start,
				 unsigned long size, pgoff_t pgoff)
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
		pr_warn("(%#lx - %#lx) is not within single vma\n",
			vma->vm_start, vma->vm_end);
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

	ret = __setup_pt_for_vma(pseudo_mm, vma, start, size >> PAGE_SHIFT,
				 pgoff);
out:
	mmap_read_unlock(mm);
	return ret;
}
