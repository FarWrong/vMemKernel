/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/atomic.h>

#ifndef HPAGE_PMD_ORDER          /* fallback if THP is off */
#define HPAGE_PMD_ORDER 9
#endif
#define SFL_ORDER          HPAGE_PMD_ORDER   /* 2 MiB on x86-64     */
#define MAX_SUPER_FREE_PAGES  64 

struct page_list {
        struct page_list *next;
        struct page *page;
};

static struct page_list *sfl_head;
static atomic_t          sfl_count   = ATOMIC_INIT(0);
static struct task_struct *sfl_thread;
static DEFINE_SPINLOCK(sfl_lock);
/* -------- eligibility test ------------------------------------------ */
static bool sfl_good(struct page *p)
{
        return true;
}

/* -------- list helpers ---------------------------------------------- */
static void sfl_add(struct page *p)
{
        struct page_list *e = kvmalloc(sizeof(*e), GFP_KERNEL);
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
        struct page_list *e = NULL;     /* list node to pop      */
        struct page_list *to_free = NULL; /* deferred free ptr   */
        struct page      *p = NULL;

        spin_lock(&sfl_lock);
        e = sfl_head;
        if (e) {
                sfl_head = e->next;
                p = e->page;
                to_free = e;             
                atomic_dec(&sfl_count);
        }
        spin_unlock(&sfl_lock);
        kvfree(to_free);
        return p;
}

/* -------- public hooks ---------------------------------------------- */
struct page *sfl_try_get(unsigned int order, gfp_t gfp_mask)
{
        if (order != SFL_ORDER)                /* only handle order-0 right now      */
               return NULL;
        return sfl_pop();
        //return NULL;
}

bool sfl_put_if_eligible(struct page *p, unsigned int order)
{
        if (order != SFL_ORDER)
            return false;
        if (!sfl_good(p))
                return false;
        if (atomic_read(&sfl_count) >= MAX_SUPER_FREE_PAGES)
                return false;

        sfl_add(p);
        return true;
}

/* -------- background restocker -------------------------------------- */
static void sfl_refill(void)
{
        while (atomic_read(&sfl_count) < MAX_SUPER_FREE_PAGES) {
                struct page *p = alloc_pages(GFP_KERNEL | __GFP_COMP | __GFP_SFL_BYPASS,
                        SFL_ORDER);
                if (!p)
                        return;
                if (sfl_good(p))
                        sfl_add(p);
                else
                    __free_pages(p, SFL_ORDER);

        }
}

static int sfl_thread_fn(void *unused)
{
        while (!kthread_should_stop()) {
                sfl_refill();
                msleep(10000);
        }
        return 0;
}

/* -------- init / late_initcall -------------------------------------- */
static int __init sfl_init(void)
{
        spin_lock_init(&sfl_lock);
        sfl_refill();
        sfl_thread = kthread_run(sfl_thread_fn, NULL, "sfl_restock");
        return PTR_ERR_OR_ZERO(sfl_thread);
}
late_initcall(sfl_init);

EXPORT_SYMBOL_GPL(sfl_try_get);
EXPORT_SYMBOL_GPL(sfl_put_if_eligible);
