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

struct page *pseudo_mm_alloc_page()
{
	struct pseudo_mm_backend *backend = pseudo_mm_get_backend();
	struct dev_dax *dev_dax = backend->filp->private_data;
	struct page *page = NULL;
	phys_addr_t phys;
	int id;

	spin_lock(&backend->lock);

	id = dax_read_lock();
	if (dev_dax->align != PAGE_SIZE) {
		pr_warn("alignment (%#x) != PAGE_SIZE\n", dev_dax->align);
		goto out;
	}

	phys = dax_pgoff_to_phys(dev_dax, backend->allocated_pg, PAGE_SIZE);
	if (phys == -1) {
		pr_warn("pgoff_to_phys(%ld) failed\n", backend->allocated_pg);
		goto out;
	}
	backend->allocated_pg++;
	page = pfn_to_page(phys >> PAGE_SHIFT);

#ifdef PSEUDO_MM_DEBUG
	pr_info("alloc page %#lx (phys addr %#llx) at pg_off %ld\n",
		(unsigned long)page, phys, backend->allocated_pg);
#endif
out:
	dax_read_unlock(id);
	spin_unlock(&backend->lock);
	return page;
}

pte_t pseudo_mm_page_to_pte(struct page *page, struct vm_fault *vmf)
{
	pte_t entry;
	struct vm_area_struct *vma = vmf->vma;
	entry = pte_mkdevmap(pfn_pte(page_to_pfn(page), vma->vm_page_prot));
	// mkwrite if needed
	if ((vmf->flags & FAULT_FLAG_WRITE) && (vma->vm_flags & VM_WRITE)) {
		entry = pte_mkyoung(entry);
		entry = maybe_mkwrite(pte_mkdirty(entry), vma);
	}
	return entry;
}
