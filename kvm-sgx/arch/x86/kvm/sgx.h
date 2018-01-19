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

#ifndef	ARCH_X86_KVM_SGX_H
#define	ARCH_X86_KVM_SGX_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/bitops.h>
#include <linux/kvm_host.h>
#include <asm/sgx.h>
#include <uapi/asm/sgx.h>	/* ENCLS error code */

int sgx_init(void);
void sgx_destroy(void);

struct kvm_epc_page {
	/* valid if physical EPC page is mapped to guest EPC gfn */
	struct sgx_epc_page *epg;
};

struct kvm_epc {
	u64 base_gfn;
	u64 npages;
	struct kvm_epc_page *epc_table;
};

/*
 * SGX capability from SGX CPUID.
 */
struct sgx_cpuinfo {
#define SGX_CAP_SGX1    (1UL << 0)
#define SGX_CAP_SGX2    (1UL << 1)
    u32 cap;
    u32 miscselect;
    u32 max_enclave_size64;
    u32 max_enclave_size32;
    u32 secs_attr_bitmask[4];
    u64 epc_base;
    u64 epc_size;
};

/*
 * SGX per-VM structure
 */
struct kvm_sgx {
	struct kvm *kvm;
	struct sgx_cpuinfo sgxinfo;
	struct kvm_epc epc;
};

#define	to_sgx(_kvm)	((struct kvm_sgx *)(kvm->arch.priv))
#define	to_epc(_sgx)	((struct kvm_epc *)(&((_sgx)->epc)))

static inline bool is_valid_epc_gfn(struct kvm *kvm, u64 gfn)
{
	struct kvm_sgx *sgx = to_sgx(kvm);
	struct kvm_epc *epc = to_epc(sgx);

	return ((gfn >= epc->base_gfn) && (gfn < epc->base_gfn + epc->npages));
}

static inline struct kvm_epc_page *gfn_to_guest_epc_page(struct kvm *kvm, u64 gfn)
{
	struct kvm_sgx *sgx = to_sgx(kvm);
	struct kvm_epc *epc = to_epc(sgx);

	BUG_ON(!is_valid_epc_gfn(kvm, gfn));

	return epc->epc_table + (gfn - epc->base_gfn);
}

static inline u64 guest_epc_page_to_gfn(struct kvm *kvm, struct kvm_epc_page *gepg)
{
	struct kvm_sgx *sgx = to_sgx(kvm);
	struct kvm_epc *epc = to_epc(sgx);

	return epc->base_gfn + (gepg - epc->epc_table);
}

/* EPC slot is created by KVM as private slot. */
#define SGX_EPC_MEMSLOT		(KVM_USER_MEM_SLOTS + 3)

int kvm_init_sgx(struct kvm *kvm, struct sgx_cpuinfo *sgxinfo);
void kvm_destroy_sgx(struct kvm *kvm);

#endif
