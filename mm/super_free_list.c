// SPDX-License-Identifier: GPL-2.0
//
// mm/super_free_list.c  (Linux 6.6.x compatible)
//
// Super Free List (SFL) of order-9 pages + DAMON-driven 2s scanning.
// - Maintains a pool of 2 MiB compound pages.
// - Exports sfl_try_get()/sfl_put_if_eligible() so THP paths can prefer SFL.
// - Runs DAMON (VA mode) on a target PID (default: largest RSS).
// - Every ~sfl_apply_ms (default 2000 ms), scans DAMON’s hot ≥2 MiB
//   regions, checks host “real huge” via hypercall at start/mid/end,
//   and demotes guest PMD-huge if the host isn’t “really huge”.
// - Debugfs:
//     /sys/kernel/debug/super_free_list/target_pid  (get/set PID)
//     /sys/kernel/debug/super_free_list/apply_ms    (get/set period ms)
//     /sys/kernel/debug/super_free_list/hot_min     (get/set hotness threshold)

#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/atomic.h>
#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/memory.h>
#include <linux/memblock.h>
#include <linux/slab.h>
#include <linux/khugepaged.h>
#include <linux/mmzone.h>
#include <linux/debugfs.h>
#include <linux/mm_types.h>
#include <linux/list.h>
#include <linux/sched/mm.h>
#include <linux/rmap.h>
#include <linux/pgtable.h>
#include <linux/huge_mm.h>
#include <linux/mmu_notifier.h>
#include <linux/damon.h>
#include <linux/pid.h>
#include <linux/seq_file.h>

#ifndef HPAGE_PMD_ORDER
#define HPAGE_PMD_ORDER 9
#endif
#define SFL_ORDER              HPAGE_PMD_ORDER   /* 2 MiB (x86-64 w/ 4 KiB base) */
#define MAX_SUPER_FREE_PAGES   64

#ifndef __GFP_SFL_BYPASS
#define __GFP_SFL_BYPASS 0
#endif

/* ===================== Super Free List ===================== */

struct page_list {
	struct page      *page;
	struct page_list *next;
};

static struct page_list *sfl_head;
static atomic_t          sfl_count = ATOMIC_INIT(0);
static DEFINE_SPINLOCK   (sfl_lock);

static struct task_struct *sfl_refill_thread;

/* ===================== DAMON driver state ===================== */

static struct damon_ctx    *sfl_damon_ctx;
static struct damon_target *sfl_damon_target;  /* save our target pointer */
static struct damos        *sfl_damon_scheme;  /* optional scheme */
static struct pid          *sfl_damon_pidp;
static struct task_struct  *sfl_scan_thread;

/* Tunables (debugfs-editable) */
static int           sfl_target_pid      = -1;
static unsigned int  sfl_apply_ms        = 2000;   /* scan period (ms) */
static unsigned int  sfl_hot_min_samples = 50;     /* accesses per aggr window */

/* ===================== Hypercall helpers ===================== */

static inline void kvm_hypercall_two_returns(unsigned long *val1,
					     unsigned long *val2,
					     unsigned long input)
{
	register unsigned long rdx asm("rdx");
	register unsigned long rsi asm("rsi");
	kvm_hypercall1(15, input);
	*val2 = rdx;
	*val1 = rsi;
}

static inline bool sfl_is_huge_flag(unsigned long flags)
{
	return (flags & (1UL << 0)) != 0;
}

static inline bool sfl_host_real_huge_by_pfn(unsigned long pfn)
{
	unsigned long h_pfn, flags;
	kvm_hypercall_two_returns(&flags, &h_pfn, (pfn << PAGE_SHIFT));
	return sfl_is_huge_flag(flags);
}

/* ===================== SFL helpers ===================== */

static void sfl_add(struct page *p)
{
	struct page_list *e = kmalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return;
	e->page = p;

	spin_lock(&sfl_lock);
	e->next = sfl_head;
	sfl_head = e;
	atomic_inc(&sfl_count);
	spin_unlock(&sfl_lock);
}

static struct page *sfl_pop(void)
{
	struct page_list *e;
	struct page *p = NULL;

	spin_lock(&sfl_lock);
	e = sfl_head;
	if (e) {
		sfl_head = e->next;
		p = e->page;
		atomic_dec(&sfl_count);
	}
	spin_unlock(&sfl_lock);

	kfree(e);
	return p;
}

/* Exported: THP paths should call this first to prefer SFL */
struct page *sfl_try_get(unsigned int order, gfp_t gfp_mask)
{
	if (order != SFL_ORDER)
		return NULL;
    printk("\nthis WORKED WORKED WORKED!!!\n");
	return sfl_pop();
}
EXPORT_SYMBOL_GPL(sfl_try_get);

/* Exported: optional recycling path if you wire it up on THP free/unmap */
bool sfl_put_if_eligible(struct page *p, unsigned int order)
{
	if (order != SFL_ORDER)
		return false;
	if (atomic_read(&sfl_count) >= MAX_SUPER_FREE_PAGES)
		return false;

	/* Optional strict policy: keep only pages host marks "real huge". */
	if (!sfl_host_real_huge_by_pfn(page_to_pfn(p)))
		return false;

	sfl_add(p);
	return true;
}
EXPORT_SYMBOL_GPL(sfl_put_if_eligible);

/* Refill SFL from buddy if underfull (verifies with hypercall) */
static void sfl_refill(void)
{
	while (atomic_read(&sfl_count) < MAX_SUPER_FREE_PAGES) {
		struct page *p = alloc_pages(GFP_KERNEL | __GFP_COMP | __GFP_SFL_BYPASS,
					     SFL_ORDER);
		if (!p)
			return;
		if (sfl_host_real_huge_by_pfn(page_to_pfn(p)))
			sfl_add(p);
		else
			__free_pages(p, SFL_ORDER);
	}
}

static int sfl_refill_thread_fn(void *unused)
{
	while (!kthread_should_stop()) {
		sfl_refill();
		msleep(10000);
	}
	return 0;
}

/* ===================== Page table helpers (PMD level only on 6.6) ===================== */

static bool vaddr_pmd_huge(struct mm_struct *mm, unsigned long addr)
{
	bool huge = false;
	pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd;

	mmap_read_lock(mm);
	pgd = pgd_offset(mm, addr);
	if (!pgd_present(*pgd)) goto out;
	p4d = p4d_offset(pgd, addr);
	if (!p4d_present(*p4d)) goto out;
	pud = pud_offset(p4d, addr);
	if (!pud_present(*pud)) goto out;

	pmd = pmd_offset(pud, addr);
	if (pmd_present(*pmd) && pmd_trans_huge(*pmd))
		huge = true;
out:
	mmap_read_unlock(mm);
	return huge;
}

/* Resolve PFN at VA: handle PMD-THP fast-path, else PTE */
static bool va_to_pfn(struct mm_struct *mm, unsigned long addr, unsigned long *out_pfn)
{
	pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd;
	pte_t *pte; spinlock_t *ptl;

	*out_pfn = 0;
	mmap_read_lock(mm);

	pgd = pgd_offset(mm, addr);
	if (!pgd_present(*pgd)) goto fail;
	p4d = p4d_offset(pgd, addr);
	if (!p4d_present(*p4d)) goto fail;
	pud = pud_offset(p4d, addr);
	if (!pud_present(*pud)) goto fail;

	pmd = pmd_offset(pud, addr);
	if (!pmd_present(*pmd)) goto fail;

	if (pmd_trans_huge(*pmd)) {
		*out_pfn = pmd_pfn(*pmd);
		mmap_read_unlock(mm);
		return true;
	}

	pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
	if (!pte_present(*pte)) { pte_unmap_unlock(pte, ptl); goto fail; }
	*out_pfn = pte_pfn(*pte);
	pte_unmap_unlock(pte, ptl);
	mmap_read_unlock(mm);
	return true;

fail:
	mmap_read_unlock(mm);
	return false;
}

/* Check start/middle/end-1page PFNs across the 2 MiB extent via hypercall */
static bool host_real_huge_for_2m_extent(struct mm_struct *mm, unsigned long va_aligned)
{
	unsigned long pfn;

	if (!va_to_pfn(mm, va_aligned, &pfn))
		return false;
	if (!sfl_host_real_huge_by_pfn(pfn))
		return false;

	if (!va_to_pfn(mm, va_aligned + (HPAGE_PMD_SIZE >> 1), &pfn))
		return false;
	if (!sfl_host_real_huge_by_pfn(pfn))
		return false;

	if (!va_to_pfn(mm, va_aligned + HPAGE_PMD_SIZE - PAGE_SIZE, &pfn))
		return false;
	if (!sfl_host_real_huge_by_pfn(pfn))
		return false;

	return true;
}

/* Demote guest PMD-huge at VA (avoid mm_find_pmd; walk explicitly) */
static void demote_if_guest_huge(struct mm_struct *mm, unsigned long va)
{
	struct vm_area_struct *vma;
	pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd;

	mmap_read_lock(mm);
	vma = find_vma(mm, va);
	if (!vma || va < vma->vm_start) {
		mmap_read_unlock(mm);
		return;
	}
	mmap_read_unlock(mm);

	if (!vaddr_pmd_huge(mm, va))
		return;

	mmap_write_lock(mm);

	pgd = pgd_offset(mm, va);
	if (!pgd_present(*pgd)) goto out_wu;
	p4d = p4d_offset(pgd, va);
	if (!p4d_present(*p4d)) goto out_wu;
	pud = pud_offset(p4d, va);
	if (!pud_present(*pud)) goto out_wu;

	pmd = pmd_offset(pud, va);
	if (pmd_present(*pmd) && pmd_trans_huge(*pmd))
		split_huge_pmd(vma, pmd, va);

out_wu:
	mmap_write_unlock(mm);
}

/* ===================== Process selection ===================== */

static int pick_largest_rss_pid(void)
{
	struct task_struct *p;
	unsigned long best = 0;
	int bestpid = -1;

	rcu_read_lock();
	for_each_process(p) {
		struct mm_struct *mm = get_task_mm(p);
		if (mm) {
			unsigned long rss = get_mm_rss(mm);
			if (rss > best) {
				best = rss;
				bestpid = task_pid_nr(p);
			}
			mmput(mm);
		}
	}
	rcu_read_unlock();
	return bestpid;
}

/* ===================== DAMON bring-up/tear-down ===================== */

static int sfl_damon_start_for_pid(int pid)
{
	printk("Starting SFL damon for %d",pid);
	int err;
	struct damon_attrs attrs = {
		.sample_interval     = 5000,     /* 5 ms */
		.aggr_interval       = 200000,   /* 200 ms */
		.ops_update_interval = 5000000,  /* 5 s */
		.min_nr_regions      = 100,
		.max_nr_regions      = 1000,
	};

	sfl_damon_pidp = find_get_pid(pid);
	if (!sfl_damon_pidp)
		return -ESRCH;

	sfl_damon_ctx = damon_new_ctx();
	if (!sfl_damon_ctx) {
		put_pid(sfl_damon_pidp);
		sfl_damon_pidp = NULL;
		return -ENOMEM;
	}

	err = damon_select_ops(sfl_damon_ctx, DAMON_OPS_VADDR);
	if (err) goto fail_ctx;

	err = damon_set_attrs(sfl_damon_ctx, &attrs);
	if (err) goto fail_ctx;

	/* Create and keep our single target pointer */
	sfl_damon_target = damon_new_target();
	if (!sfl_damon_target) { err = -ENOMEM; goto fail_ctx; }
	sfl_damon_target->pid = sfl_damon_pidp;  /* VA-mode target id */
	damon_add_target(sfl_damon_ctx, sfl_damon_target);

	/* Optional: a scheme to bias toward promotion; not strictly required */
	sfl_damon_scheme = kzalloc(sizeof(*sfl_damon_scheme), GFP_KERNEL);
	if (!sfl_damon_scheme) { err = -ENOMEM; goto fail_ctx; }
	INIT_LIST_HEAD(&sfl_damon_scheme->filters);

	sfl_damon_scheme->pattern.min_sz_region   = HPAGE_PMD_SIZE;
	sfl_damon_scheme->pattern.max_sz_region   = ULONG_MAX;
	sfl_damon_scheme->pattern.min_nr_accesses = sfl_hot_min_samples;
	sfl_damon_scheme->pattern.max_nr_accesses = UINT_MAX;
	sfl_damon_scheme->pattern.min_age_region  = 0;
	sfl_damon_scheme->pattern.max_age_region  = UINT_MAX;
	sfl_damon_scheme->action                  = DAMOS_HUGEPAGE;

	damon_set_schemes(sfl_damon_ctx, &sfl_damon_scheme, 1);

	err = damon_start(&sfl_damon_ctx, 1, false);
	if (err) goto fail_scheme;

	return 0;

fail_scheme:
	kfree(sfl_damon_scheme);
	sfl_damon_scheme = NULL;
fail_ctx:
	sfl_damon_target = NULL;
	if (sfl_damon_ctx)
		sfl_damon_ctx = NULL;
	if (sfl_damon_pidp) {
		put_pid(sfl_damon_pidp);
		sfl_damon_pidp = NULL;
	}
	return err;
}

static void sfl_damon_stop(void)
{
	if (sfl_damon_ctx) {
		damon_stop(&sfl_damon_ctx, 1);
		if (sfl_damon_scheme) {
			kfree(sfl_damon_scheme);
			sfl_damon_scheme = NULL;
		}
		if (sfl_damon_pidp) {
			put_pid(sfl_damon_pidp);
			sfl_damon_pidp = NULL;
		}
		sfl_damon_target = NULL;
		sfl_damon_ctx = NULL;
	}
}

/* ===================== 2s scanning driver ===================== */

static void sfl_scan_hotspots_once(void)
{
	printk("scannning hot spots");
	struct task_struct *task;
	struct mm_struct *mm;

	if (!sfl_damon_ctx || !sfl_damon_target)
		return;

	task = get_pid_task(sfl_damon_target->pid, PIDTYPE_PID);
	if (!task)
		return;
	mm = get_task_mm(task);
	if (!mm) {
		put_task_struct(task);
		return;
	}

	/* Iterate regions safely enough for our purpose (best-effort) */
	{
		struct damon_region *r;
		printk("Iterating");
		damon_for_each_region(r, sfl_damon_target) {
			unsigned long len = r->ar.end - r->ar.start;
			unsigned long va_aligned;

			if (len < HPAGE_PMD_SIZE)
				continue;
			if (r->nr_accesses < sfl_hot_min_samples)
				continue;
				printk("not enough samples");
			printk("GOt through");
			va_aligned = ALIGN_DOWN(r->ar.start, HPAGE_PMD_SIZE);

			/* If host isn’t really huge across the 2 MiB extent, demote guest PMD to force fresh allocation */
			if (!host_real_huge_for_2m_extent(mm, va_aligned))
				demote_if_guest_huge(mm, va_aligned);
		}
	}

	mmput(mm);
	put_task_struct(task);
}

static int sfl_scan_thread_fn(void *unused)
{
	while (!kthread_should_stop()) {
		sfl_scan_hotspots_once();
		msleep_interruptible(sfl_apply_ms ? sfl_apply_ms : 2000);
	}
	return 0;
}

/* ===================== debugfs controls ===================== */

static struct dentry *sfl_debugfs_dir;

static int dbg_target_pid_set(void *data, u64 val)
{
	int pid = (int)val;
	int err;

	/* stop current */
	sfl_damon_stop();

	if (pid > 0) {
		err = sfl_damon_start_for_pid(pid);
		if (err)
			return err;
		sfl_target_pid = pid;
	} else {
		sfl_target_pid = -1;
	}
	return 0;
}
static int dbg_target_pid_get(void *data, u64 *val)
{
	*val = (u64)sfl_target_pid;
	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(sfl_target_pid_fops,
			dbg_target_pid_get,
			dbg_target_pid_set,
			"%llu\n");

static int dbg_apply_ms_set(void *data, u64 val)
{
	sfl_apply_ms = (unsigned int)val;
	return 0;
}
static int dbg_apply_ms_get(void *data, u64 *val)
{
	*val = (u64)sfl_apply_ms;
	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(sfl_apply_ms_fops,
			dbg_apply_ms_get,
			dbg_apply_ms_set,
			"%llu\n");

static int dbg_hot_min_set(void *data, u64 val)
{
	sfl_hot_min_samples = (unsigned int)val;
	if (sfl_damon_scheme)
		sfl_damon_scheme->pattern.min_nr_accesses = sfl_hot_min_samples;
	return 0;
}
static int dbg_hot_min_get(void *data, u64 *val)
{
	*val = (u64)sfl_hot_min_samples;
	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(sfl_hot_min_fops,
			dbg_hot_min_get,
			dbg_hot_min_set,
			"%llu\n");

/* ===================== init ===================== */

static int __init sfl_init(void)
{
	int err;

	spin_lock_init(&sfl_lock);

	/* Start SFL restocker */
	sfl_refill();
	sfl_refill_thread = kthread_run(sfl_refill_thread_fn, NULL, "sfl_restock");
	err = PTR_ERR_OR_ZERO(sfl_refill_thread);
	if (err) {
		pr_err("sfl: restocker start failed: %d\n", err);
		return err;
	}

	/* debugfs controls */
	sfl_debugfs_dir = debugfs_create_dir("super_free_list", NULL);
	if (sfl_debugfs_dir) {
		debugfs_create_file("target_pid", 0600, sfl_debugfs_dir, NULL, &sfl_target_pid_fops);
		debugfs_create_file("apply_ms",  0600, sfl_debugfs_dir, NULL, &sfl_apply_ms_fops);
		debugfs_create_file("hot_min",   0600, sfl_debugfs_dir, NULL, &sfl_hot_min_fops);
	}

	/* Pick largest-RSS process by default and start DAMON */
	sfl_target_pid = pick_largest_rss_pid();
	if (sfl_target_pid >= 0) {
		err = sfl_damon_start_for_pid(sfl_target_pid);
		if (err)
			pr_warn("sfl: DAMON start failed: %d\n", err);
	} else {
		pr_warn("sfl: no candidate process for DAMON\n");
	}

	/* Start periodic scan thread (~2s by default) */
	sfl_scan_thread = kthread_run(sfl_scan_thread_fn, NULL, "sfl_scan");
	err = PTR_ERR_OR_ZERO(sfl_scan_thread);
	if (err)
		pr_warn("sfl: scan thread start failed: %d\n", err);

	pr_info("sfl: init done (pid=%d, hot>=%u, period=%ums)\n",
		sfl_target_pid, sfl_hot_min_samples, sfl_apply_ms);
	return 0;
}
late_initcall(sfl_init);
