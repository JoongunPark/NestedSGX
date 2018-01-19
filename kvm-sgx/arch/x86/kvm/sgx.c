/*
 * KVM SGX Virtualization support.
 *
 * Copyright (c) 2015, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 * Author:	Kai Huang <kai.huang@linux.intel.com>
 */

#include <linux/kvm_host.h>
#include <asm/cpufeature.h>	/* boot_cpu_has */
#include <asm/processor.h>	/* cpuid */
#include <linux/smp.h>
#include <linux/module.h>
#include "sgx.h"

/* Debug helpers... */
#define	sgx_debug(fmt, ...)	\
	printk(KERN_DEBUG "KVM: SGX: %s: "fmt, __func__, ## __VA_ARGS__)
#define	sgx_info(fmt, ...)	\
	printk(KERN_INFO "KVM: SGX: "fmt, ## __VA_ARGS__)
#define	sgx_err(fmt, ...)	\
	printk(KERN_ERR "KVM: SGX: "fmt, ## __VA_ARGS__)

/*
 * EPC pages are managed by SGX driver. KVM needs to call SGX driver's APIs
 * to allocate/free EPC page, etc.
 *
 * However KVM cannot call SGX driver's APIs directly. As on machine without
 * SGX support, SGX driver cannot be loaded, therefore if KVM calls driver's
 * APIs directly, KVM won't be able to be loaded either, which is not
 * acceptable. Instead, KVM uses symbol_get{put} pair to get driver's APIs
 * at runtime and simply disable SGX if those symbols cannot be found.
 */
struct required_sgx_driver_symbols {
	struct sgx_epc_page *(*alloc_epc_page)(unsigned int flags);
	/*
	 * Currently SGX driver's sgx_free_page has 'struct sgx_encl *encl'
	 * as parameter. We need to honor that.
	 */
	int (*free_epc_page)(struct sgx_epc_page *epg, struct sgx_encl *encl);
	/*
	 * get/put (map/unmap) kernel virtual address of given EPC page.
	 * The namings are aligned to SGX driver's APIs.
	 */
	void *(*get_epc_page)(struct sgx_epc_page *epg);
	void (*put_epc_page)(void *epc_page_vaddr);
};

static struct required_sgx_driver_symbols sgx_driver_symbols = {
	.alloc_epc_page = NULL,
	.free_epc_page = NULL,
	.get_epc_page = NULL,
	.put_epc_page = NULL,
};

static inline struct sgx_epc_page *sgx_alloc_epc_page(unsigned int flags)
{
	struct sgx_epc_page *epg;

	BUG_ON(!sgx_driver_symbols.alloc_epc_page);

	epg = sgx_driver_symbols.alloc_epc_page(flags);

	/* sgx_alloc_page returns ERR_PTR(error_code) instead of NULL */
	return IS_ERR_OR_NULL(epg) ? NULL : epg;
}

static inline void sgx_free_epc_page(struct sgx_epc_page *epg)
{
	BUG_ON(!sgx_driver_symbols.free_epc_page);

	sgx_driver_symbols.free_epc_page(epg, NULL);
}

static inline void *sgx_kmap_epc_page(struct sgx_epc_page *epg)
{
	BUG_ON(!sgx_driver_symbols.get_epc_page);

	return sgx_driver_symbols.get_epc_page(epg);
}

static inline void sgx_kunmap_epc_page(void *addr)
{
	BUG_ON(!sgx_driver_symbols.put_epc_page);

	sgx_driver_symbols.put_epc_page(addr);
}

static inline u64 sgx_epc_page_to_pfn(struct sgx_epc_page *epg)
{
	return (u64)(epg->pa >> PAGE_SHIFT);
}

static int __sgx_eremove(struct sgx_epc_page *epg)
{
	void *addr;
	int r;

	addr = sgx_kmap_epc_page(epg);
	r = __eremove(addr);
	sgx_kunmap_epc_page(addr);
	if (unlikely(r)) {
		sgx_err("__eremove error: EPC pfn 0x%lx, r %d\n",
				(unsigned long)sgx_epc_page_to_pfn(epg),
				r);
	}

	return r;
}

/* By reaching here the mmap_sem should be already hold */
static int kvm_epc_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct kvm_sgx *sgx = (struct kvm_sgx *)vma->vm_private_data;
	struct kvm *kvm;
	struct sgx_epc_page *epg;
	struct kvm_epc_page *gepg;
	u64 gfn, pfn;

	BUG_ON(!sgx);
	kvm = sgx->kvm;

	gfn = to_epc(sgx)->base_gfn + (((unsigned long)vmf->address -
				vma->vm_start) >> PAGE_SHIFT);
	gepg = gfn_to_guest_epc_page(kvm, gfn);

	/*
	 * SGX driver doesn't support recycling EPC pages back from KVM
	 * guests yet, and it doesn't support out-of-EPC killer either,
	 * therefore if we don't use SGX_ALLOC_ATOMIC here, this function
	 * may never return in case SGX driver cannot recycle enough EPC
	 * pages from host SGX applications.
	 */
	epg = sgx_alloc_epc_page(SGX_ALLOC_ATOMIC);
	if (!epg) {
		/* Unable to allocate EPC. Kill the guest */
		sgx_err("kvm 0x%p, gfn 0x%lx: out of EPC when trying to "
				"map EPC to guest.\n", kvm, (unsigned long)gfn);
		goto error;
	}

	pfn = sgx_epc_page_to_pfn(epg);
	if (vm_insert_pfn(vma, (unsigned long)vmf->address,
			(unsigned long)pfn)) {
		sgx_err("kvm 0x%p, gfn 0x%lx: failed to install host mapping "
				"on: hva 0x%lx, pfn 0x%lx\n", kvm,
				(unsigned long)gfn,
				(unsigned long)vmf->address,
				(unsigned long)pfn);
		sgx_free_epc_page(epg);
		goto error;
	}

	/* Book keeping physical EPC page allocated/mapped to particular GFN */
	gepg->epg = epg;

	return VM_FAULT_NOPAGE;	/* EPC has not 'struct page' associated */
error:
	return VM_FAULT_SIGBUS;
}

static void kvm_epc_close(struct vm_area_struct *vma)
{
}

static struct vm_operations_struct kvm_epc_ops =  {
	.fault = kvm_epc_fault,
	/* close to prevent vma to be merged. */
	.close = kvm_epc_close,
};

static void kvm_init_epc_table(struct kvm_epc_page *epc_table, u64 npages)
{
	u64 i;

	for (i = 0; i < npages; i++)  {
		struct kvm_epc_page *gepg = epc_table + i;

		gepg->epg = NULL;
	}
}

static void kvm_destroy_epc_table(struct kvm_epc_page *epc_table,
		u64 npages)
{
	u64 i;
	int r;

	/*
	 *
	 */
	/*
	 * We need to call EREMOVE explicitly but not sgx_free_epc_page here
	 * for the first round as sgx_free_page (sgx_free_epc_page calls it)
	 * provided by SGX driver always does EREMOVE and adds EPC page back
	 * to sgx_free_list if there's no error. We don't keep SECS page to
	 * a temporary list but rely on sgx_free_epc_page to free all EPC pages
	 * in second round so just use EREMOVE at first round.
	 */
	for (i = 0; i < npages; i++) {
		struct kvm_epc_page *gepg = epc_table + i;
		struct sgx_epc_page *epg;

		if (!gepg->epg)
			continue;

		epg = gepg->epg;
		r = __sgx_eremove(epg);
		if (r == SGX_CHILD_PRESENT) {
			sgx_debug("EREMOVE SECS (0x%lx) prior to regular EPC\n",
				(unsigned long)sgx_epc_page_to_pfn(epg));
		}
	}

	/*
	 * EREMOVE on invalid EPC (which has been removed from enclave) will
	 * simply return success.
	 */
	for (i = 0; i < npages; i++) {
		struct kvm_epc_page *gepg = epc_table + i;
		struct sgx_epc_page *epg;

		if (!gepg->epg)
			continue;

		epg = gepg->epg;
		sgx_free_epc_page(epg);
	}
}

static int kvm_init_epc(struct kvm *kvm, u64 epc_base_pfn, u64 epc_npages)
{
	struct kvm_sgx *sgx = to_sgx(kvm);
	struct vm_area_struct *vma;
	struct kvm_memory_slot *slot;
	struct kvm_epc_page *epc_table;
	int r;

	r = x86_set_memory_region(kvm, SGX_EPC_MEMSLOT,
			epc_base_pfn << PAGE_SHIFT, epc_npages << PAGE_SHIFT);
	if (r) {
		sgx_debug("x86_set_memory_region failed: %d\n", r);
		return r;
	}

	slot = id_to_memslot(kvm_memslots(kvm), SGX_EPC_MEMSLOT);
	BUG_ON(!slot);

	epc_table = alloc_pages_exact(epc_npages * sizeof (struct kvm_epc_page),
			GFP_KERNEL);
	if (!epc_table) {
		sgx_debug("unable to alloc guest EPC table.\n");
		x86_set_memory_region(kvm, SGX_EPC_MEMSLOT, 0, 0);
		return -ENOMEM;
	}

	kvm_init_epc_table(epc_table, epc_npages);

	sgx->epc.epc_table = epc_table;
	sgx->epc.base_gfn = slot->base_gfn;
	sgx->epc.npages = slot->npages;

	vma = find_vma_intersection(kvm->mm, slot->userspace_addr,
			slot->userspace_addr + 1);
	BUG_ON(!vma);

	/* EPC has no 'struct page' associated */
	vma->vm_flags |= VM_PFNMAP;
	vma->vm_flags &= ~(VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC | VM_MAYSHARE);
	vma->vm_ops = &kvm_epc_ops;
	vma->vm_private_data = (void *)sgx;

	return 0;
}

static void kvm_destroy_epc(struct kvm *kvm)
{
	struct kvm_sgx *sgx = to_sgx(kvm);
	struct kvm_epc_page *epc_table = to_epc(sgx)->epc_table;
	u64 npages = to_epc(sgx)->npages;

	/*
	 * See kvm_arch_destroy_vm, which is also the reason that we don't
	 * keep slot in kvm_epc structure, as slot may already have been
	 * destroyed during abnormal exit.
	 */
	if (current->mm == kvm->mm)
		x86_set_memory_region(kvm, SGX_EPC_MEMSLOT, 0, 0);

	kvm_destroy_epc_table(epc_table, npages);

	free_pages_exact(epc_table, npages * sizeof (struct kvm_epc_page));
}

static int kvm_populate_epc(struct kvm *kvm, u64 epc_base_pfn,
		u64 epc_npages)
{
	int i;

	for (i = 0; i < epc_npages; i++) {
		gfn_t gfn = epc_base_pfn + i;
		/* This will trigger vma->vm_ops->fault to populate EPC */
		kvm_pfn_t pfn = gfn_to_pfn(kvm, gfn);
		if (is_error_pfn(pfn))
			return -EFAULT;	/* Cannot use ENOMEM */
	}
	return 0;
}

/*
 * Initialize SGX for particular guest. This function may be called several
 * times from caller. If guest SGX has not been initialized (this function is
 * firstly called), we create kvm_sgx structure and initialize it. If guest SGX
 * has already been initialized, we then check whether SGX cpuid from Qemu is
 * consistent with existing one. If Qemu did something wrong by returning error
 * here we can allow Qemu to stop creating vcpu, or just kill guest. We also
 * populate all EPC for guest if oversubscription is not supported.
 */
int kvm_init_sgx(struct kvm *kvm, struct sgx_cpuinfo *sgxinfo)
{
	struct kvm_sgx *sgx = to_sgx(kvm);
	u64 epc_base_pfn, epc_npages;
	int r;

	if (!sgxinfo)
		return -EINVAL;

	if (sgx) {
		/*
		 * Already inited? We then check whether EPC base and size
		 * equal to saved value.
		 */

		if (memcmp(&(sgx->sgxinfo), sgxinfo,
					sizeof(struct sgx_cpuinfo))) {
			sgx_debug("SGX CPUID inconsistency from Qemu\n");
			return -EINVAL;
		}
		else
			return 0;
	}

	epc_base_pfn = sgxinfo->epc_base  >> PAGE_SHIFT;
	epc_npages = sgxinfo->epc_size >> PAGE_SHIFT;

	sgx = kzalloc(sizeof(struct kvm_sgx), GFP_KERNEL);
	if (!sgx) {
		sgx_debug("out of memory\n");
		return -ENOMEM;
	}
	sgx->kvm = kvm;
	memcpy(&(sgx->sgxinfo), sgxinfo, sizeof(struct sgx_cpuinfo));
	/* Make to_sgx(kvm) work */
	kvm->arch.priv = sgx;

	/* Init EPC for guest */
	r = kvm_init_epc(kvm, epc_base_pfn, epc_npages);
	if (r) {
		sgx_debug("kvm_create_epc_slot failed.\n");
		kfree(sgx);
		kvm->arch.priv = NULL;
		return r;
	}

	/* Populate all EPC pages for guest when it is created. */
	r = kvm_populate_epc(kvm, epc_base_pfn, epc_npages);
	if (r) {
		sgx_debug("kvm_populate_epc failed.\n");
		/* EPC slot will be destroyed when guest is destoryed */
		kvm_destroy_epc(kvm);
		kfree(sgx);
		kvm->arch.priv = NULL;
		return r;
	}

	return 0;
}

void kvm_destroy_sgx(struct kvm *kvm)
{
	struct kvm_sgx *sgx = to_sgx(kvm);

	if (sgx) {
		kvm_destroy_epc(kvm);
		kfree(sgx);
	}

	kvm->arch.priv = NULL;
}



static void put_sgx_driver_symbols(void);

static int get_sgx_driver_symbols(void)
{
	sgx_driver_symbols.alloc_epc_page = symbol_get(sgx_alloc_page);
	if (!sgx_driver_symbols.alloc_epc_page)
		goto error;
	sgx_driver_symbols.free_epc_page = symbol_get(sgx_free_page);
	if (!sgx_driver_symbols.free_epc_page)
		goto error;
	sgx_driver_symbols.get_epc_page = symbol_get(sgx_get_page);
	if (!sgx_driver_symbols.get_epc_page)
		goto error;
	sgx_driver_symbols.put_epc_page = symbol_get(sgx_put_page);
	if (!sgx_driver_symbols.put_epc_page)
		goto error;

	return 0;

error:
	put_sgx_driver_symbols();
	return -EFAULT;
}

static void put_sgx_driver_symbols(void)
{
	if (sgx_driver_symbols.alloc_epc_page)
		symbol_put(sgx_alloc_page);
	if (sgx_driver_symbols.free_epc_page)
		symbol_put(sgx_free_page);
	if (sgx_driver_symbols.get_epc_page)
		symbol_put(sgx_get_page);
	if (sgx_driver_symbols.put_epc_page)
		symbol_put(sgx_put_page);

	memset(&sgx_driver_symbols, 0, sizeof (sgx_driver_symbols));
}

int sgx_init(void)
{
	int r;

	r = get_sgx_driver_symbols();
	if (r) {
		sgx_err("SGX driver is not loaded.\n");
		return r;
	}

	sgx_info("SGX virtualization supported.\n");

	return 0;
}

void sgx_destroy(void)
{
	put_sgx_driver_symbols();
}
