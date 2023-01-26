#include <linux/filter.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <ptrace.h>

#include "common/config.h"
#include "imgset.h"
#include "kcmp.h"
#include "pstree.h"
#include <compel/ptrace.h>
#include "proc_parse.h"
#include "restorer.h"
#include "syscall_user_dispatch.h"
#include "servicefd.h"
#include "util.h"
#include "rst-malloc.h"

#include "protobuf.h"
//#include "images/seccomp.pb-c.h"

#undef LOG_PREFIX
#define LOG_PREFIX "syscall_dispatch: "

static struct rb_root sud_tid_rb_root = RB_ROOT;
static struct sud_entry *sud_tid_entry_root;

static SUDEntry *sud_img_entry;

struct sud_entry *sud_lookup(pid_t tid_real, bool create, bool mandatory)
{
	struct sud_entry *entry = NULL;

	struct rb_node *node = sud_tid_rb_root.rb_node;
	struct rb_node **new = &sud_tid_rb_root.rb_node;
	struct rb_node *parent = NULL;

	while (node) {
		struct sud_entry *this = rb_entry(node, struct sud_entry, node);

		parent = *new;
		if (tid_real < this->tid_real)
			node = node->rb_left, new = &((*new)->rb_left);
		else if (tid_real > this->tid_real)
			node = node->rb_right, new = &((*new)->rb_right);
		else
			return this;
	}

	if (create) {
		entry = xzalloc(sizeof(*entry));
		if (!entry)
			return NULL;
		rb_init_node(&entry->node);
		entry->tid_real = tid_real;

		entry->next = sud_tid_entry_root, sud_tid_entry_root = entry;
		rb_link_and_balance(&sud_tid_rb_root, &entry->node, parent, new);
	} else {
		if (mandatory)
			pr_err("Can't find entry on tid_real %d\n", tid_real);
	}

	return entry;
}

int sud_collect_entry(pid_t tid_real, unsigned int mode)
{
	struct sud_entry *entry;

	entry = sud_lookup(tid_real, true, false);
	if (!entry) {
		pr_err("Can't create entry on tid_real %d\n", tid_real);
		return -1;
	}
	entry->mode = mode;

	pr_debug("Collected tid_real %d mode %#x\n", tid_real, mode);
	return 0;
}

void sud_free_entries(void)
{
	struct sud_entry *entry, *next;

	for (entry = sud_tid_entry_root; entry; entry = next) {
		next = entry->next;
		xfree(entry);
	}

	sud_tid_rb_root = RB_ROOT;
	sud_tid_entry_root = NULL;
}

int sud_dump_thread(pid_t tid_real, ThreadCoreEntry *thread_core)
{
	struct sud_entry *entry = sud_find_entry(tid_real);
	if (!entry) {
		pr_err("Can't dump thread core on tid_real %d\n", tid_real);
		return -1;
	}
	thread_core->has_syscall_user_dispatch = entry->sud_cfg.mode == PR_SYS_DISPATCH_ON;
	return 0;
}

static int collect_sud_config(struct pstree_item *item)
{
	struct sud_entry *leader, *entry;
	size_t i;

	if (item->pid->state == TASK_DEAD)
		return 0;

	leader = sud_find_entry(item->pid->real);
	if (!leader) {
		pr_err("Can't collect SUD on leader tid_real %d\n", item->pid->real);
		return -1;
	}

	for (i = 0; i < item->nr_threads; i++) {
		entry = sud_find_entry(item->threads[i].real);
		if (!entry) {
			pr_err("Can't collect SUD on tid_real %d\n", item->pid->real);
			return -1;
		}

		if (ptrace(PTRACE_GET_SYSCALL_USER_DISPATCH_CONFIG, entry->tid_real,
					     entry->sud_cfg, sizeof(entry->sud_cfg)) < 0)
			return -1;
	}

	return 0;
}

int dump_sud(void)
{

}

int sud_collect_dump(void)
{
	if (preorder_pstree_traversal(root_item, collect_sud_config) < 0)
		return -1;

	if (dump_sud())
		return -1;

	return 0;
}

/* The sud_img_entry will be shared between all children */
int sud_read_image(void)
{
	struct cr_img *img;
	int ret;

	img = open_image(CR_FD_SYSCALL_USER_DISPATCH, O_RSTR);
	if (!img)
		return -1;

	ret = pb_read_one_eof(img, &sud_img_entry, PB_SYSCALL_USER_DISPATCH);
	close_image(img);
	if (ret <= 0)
		return 0; /* there were no filters */

	BUG_ON(!sud_img_entry);

	return 0;
}

/* sud_img_entry will be freed per-children after forking */
static void free_sud_filters(void)
{
	if (sud_img_entry) {
		sud_entry__free_unpacked(sud_img_entry, NULL);
		sud_img_entry = NULL;
	}
}

void sud_rst_reloc(struct thread_restore_args *args)
{
	size_t j, off;

	if (!args->sud_filters_n)
		return;

	args->sud_filters = rst_mem_remap_ptr(args->sud_filters_pos, RM_PRIVATE);
	args->sud_filters_data =
		(void *)args->sud_filters + args->sud_filters_n * sizeof(struct thread_sud_filter);

	for (j = off = 0; j < args->sud_filters_n; j++) {
		struct thread_sud_filter *f = &args->sud_filters[j];

		f->sock_fprog.filter = args->sud_filters_data + off;
		off += f->sock_fprog.len * sizeof(struct sock_filter);
	}
}

int sud_prepare_threads(struct pstree_item *item, struct task_restore_args *ta)
{
	struct thread_restore_args *args_array = (struct thread_restore_args *)(&ta[1]);
	size_t i, j, nr_filters, filters_size, rst_size, off;

	for (i = 0; i < item->nr_threads; i++) {
		ThreadCoreEntry *thread_core = item->core[i]->thread_core;
		struct thread_restore_args *args = &args_array[i];
		SeccompFilter *sf;

		args->sud_mode = SECCOMP_MODE_DISABLED;
		args->sud_filters_pos = 0;
		args->sud_filters_n = 0;
		args->sud_filters = NULL;
		args->sud_filters_data = NULL;

		if (thread_core->has_sud_mode)
			args->sud_mode = thread_core->sud_mode;

		if (args->sud_mode != SECCOMP_MODE_FILTER)
			continue;

		if (thread_core->sud_filter >= sud_img_entry->n_sud_filters) {
			pr_err("Corrupted filter index on tid %d (%u > %zu)\n", item->threads[i].ns[0].virt,
			       thread_core->sud_filter, sud_img_entry->n_sud_filters);
			return -1;
		}

		sf = sud_img_entry->sud_filters[thread_core->sud_filter];
		if (sf->filter.len % (sizeof(struct sock_filter))) {
			pr_err("Corrupted filter len on tid %d (index %u)\n", item->threads[i].ns[0].virt,
			       thread_core->sud_filter);
			return -1;
		}
		filters_size = sf->filter.len;
		nr_filters = 1;

		while (sf->has_prev) {
			if (sf->prev >= sud_img_entry->n_sud_filters) {
				pr_err("Corrupted filter index on tid %d (%u > %zu)\n", item->threads[i].ns[0].virt,
				       sf->prev, sud_img_entry->n_sud_filters);
				return -1;
			}

			sf = sud_img_entry->sud_filters[sf->prev];
			if (sf->filter.len % (sizeof(struct sock_filter))) {
				pr_err("Corrupted filter len on tid %d (index %u)\n", item->threads[i].ns[0].virt,
				       sf->prev);
				return -1;
			}
			filters_size += sf->filter.len;
			nr_filters++;
		}

		args->sud_filters_n = nr_filters;

		rst_size = filters_size + nr_filters * sizeof(struct thread_sud_filter);
		args->sud_filters_pos = rst_mem_align_cpos(RM_PRIVATE);
		args->sud_filters = rst_mem_alloc(rst_size, RM_PRIVATE);
		if (!args->sud_filters) {
			pr_err("Can't allocate %zu bytes for filters on tid %d\n", rst_size,
			       item->threads[i].ns[0].virt);
			return -ENOMEM;
		}
		args->sud_filters_data =
			(void *)args->sud_filters + nr_filters * sizeof(struct thread_sud_filter);

		sf = sud_img_entry->sud_filters[thread_core->sud_filter];
		for (j = off = 0; j < nr_filters; j++) {
			struct thread_sud_filter *f = &args->sud_filters[j];

			f->sock_fprog.len = sf->filter.len / sizeof(struct sock_filter);
			f->sock_fprog.filter = args->sud_filters_data + off;
			f->flags = sf->flags;

			memcpy(f->sock_fprog.filter, sf->filter.data, sf->filter.len);

			off += sf->filter.len;
			sf = sud_img_entry->sud_filters[sf->prev];
		}
	}

	free_sud_filters();
	return 0;
}
