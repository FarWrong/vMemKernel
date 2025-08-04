
#include <linux/types.h>
#include <linux/mm.h>

/* ---- extern hooks implemented in mm/super_free_list.c ---- */
struct page *sfl_try_get(unsigned int order, gfp_t gfp_mask);
bool         sfl_put_if_eligible(struct page *page, unsigned int order);