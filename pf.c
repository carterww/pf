#define _GNU_SOURCE

#include <pf.h>

#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>

struct {
	uint64_t val;
	bool fetched;
} pf_type_hw_ecore_config_values[] = {
	[PERF_COUNT_HW_CPU_CYCLES] = { 0, false },
	[PERF_COUNT_HW_INSTRUCTIONS] = { 0, false },
	[PERF_COUNT_HW_CACHE_REFERENCES] = { 0, false },
	[PERF_COUNT_HW_CACHE_MISSES] = { 0, false },
	[PERF_COUNT_HW_BRANCH_INSTRUCTIONS] = { 0, false },
	[PERF_COUNT_HW_BRANCH_MISSES] = { 0, false },
	[PERF_COUNT_HW_BUS_CYCLES] = { 0, false },
	[PERF_COUNT_HW_STALLED_CYCLES_FRONTEND] = { 0, false },
	[PERF_COUNT_HW_STALLED_CYCLES_BACKEND] = { 0, false },
	[PERF_COUNT_HW_REF_CPU_CYCLES] = { 0, false },
};

extern const char *const PF_PERF_TYPE_HW_TO_ECORE_CONFIG_PATHS[];
extern const size_t PF_PERF_TYPE_HW_TO_ECORE_CONFIG_PATHS_LENGTH;
extern const char *PF_ECORE_TYPE_PATH;

/* x86_64 is TSO, store->store won't be reordered. Compiler could still reorder */
inline static void ssfence(void)
{
	__asm__ __volatile__("" ::: "memory");
}

inline static long sys_perf_open(struct perf_event_attr *pattr, pid_t pid,
				 int cpu, int groupfd, unsigned long flags)
{
	return syscall(SYS_perf_event_open, pattr, pid, cpu, groupfd, flags);
}

inline static bool pf_ecore_type(uint32_t *val)
{
	static uint32_t t = 0;
	static bool fetched = false;

	int ecore_fd;
	ssize_t nbytes;
	char buf[32] = { 0 };

	if (fetched) {
		*val = t;
		return true;
	}

	ecore_fd = open(PF_ECORE_TYPE_PATH, O_RDONLY);
	if (ecore_fd == -1) {
		return false;
	}
	if ((nbytes = read(ecore_fd, buf, 31)) == -1) {
		return false;
	}
	if (nbytes == 0) {
		return false;
	}
	t = (uint32_t)strtoul(buf, NULL, 10);
	if (t == 0) {
		return false;
	}
	ssfence();
	fetched = true;
	close(ecore_fd);

	*val = t;

	return true;
}

inline static bool pf_ecore_config(enum perf_hw_id perf_cfg, uint64_t *val)
{
	const char *path;
	char buf[64] = { 0 };
	int fd;
	ssize_t nbytes;

	if (perf_cfg >= PF_PERF_TYPE_HW_TO_ECORE_CONFIG_PATHS_LENGTH) {
		return false;
	}
	path = PF_PERF_TYPE_HW_TO_ECORE_CONFIG_PATHS[perf_cfg];
	if (path == NULL) {
		return false;
	}
	if (pf_type_hw_ecore_config_values[perf_cfg].fetched == true) {
		return pf_type_hw_ecore_config_values[perf_cfg].val;
	}

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		return false;
	}

	nbytes = read(fd, buf, 63);
	if (nbytes == -1) {
		close(fd);
		return false;
	}

	char *eventn = strstr(buf, "event=");
	if (eventn == NULL) {
		close(fd);
		return false;
	}
	eventn += 6;
	*val = strtoull(eventn, NULL, 16);

	pf_type_hw_ecore_config_values[perf_cfg].val = *val;
	ssfence();
	pf_type_hw_ecore_config_values[perf_cfg].fetched = true;

	printf("%d: %lu\n", perf_cfg, *val);

	close(fd);
	return true;
}

inline static void
pf_open_args_to_perf_event_attr(const struct pf_open_args *pf,
				struct perf_event_attr *a, bool is_leader)
{
	uint32_t type = pf->type;

	memset(a, 0, sizeof(*a));
	a->type = pf->type;
	a->size = sizeof(*a);
	switch (a->type) {
	case PERF_TYPE_HARDWARE:
		a->config = pf->type_specific.hw;
		break;
	case PERF_TYPE_SOFTWARE:
		a->config = pf->type_specific.sw;
		break;
	case PERF_TYPE_HW_CACHE:
		a->config = (pf->type_specific.cache.id) |
			    (pf->type_specific.cache.op << 8) |
			    (pf->type_specific.cache.op_result << 16);
		break;
	default:
		break;
	}
	a->read_format = pf->grouped ? PERF_FORMAT_GROUP : 0;
	a->disabled = is_leader ? 1 : 0;
	a->exclude_user = pf->exclude_user ? 1 : 0;
	a->exclude_kernel = pf->exclude_kernel ? 1 : 0;
	a->exclude_hv = pf->exclude_hypervisor ? 1 : 0;
	a->exclude_idle = pf->exclude_idle ? 1 : 0;
}

inline static bool pf_pmu_group_add(struct pf_pmu_group *group, int fd,
				    struct pf_open_args *arg)
{
	if (group->nopen == group->cap) {
		unsigned long new_cap = group->cap * 2;
		group->fds = realloc(group->fds, sizeof(*group->fds) * new_cap);
		if (group->fds == NULL) {
			return false;
		}
		group->events = realloc(group->events,
					sizeof(*group->events) * new_cap);
		if (group->events == NULL) {
			return false;
		}
		group->cap = new_cap;
	}
	group->fds[group->nopen] = fd;
	group->events[group->nopen] = *arg;
	group->nopen += 1;

	return true;
}

inline static struct pf_pmu_group *pf_pmu_group_allocate(bool is_grouped)
{
	struct pf_pmu_group *g = NULL;

	unsigned long initial_len = is_grouped ? 8 : 1;

	g = malloc(sizeof(*g));
	if (g == NULL) {
		return NULL;
	}
	g->nopen = 0;
	g->cap = initial_len;
	g->fds = malloc(sizeof(*g->fds) * initial_len);
	if (g->fds == NULL) {
		free(g);
		return NULL;
	}
	g->events = malloc(sizeof(*g->events) * initial_len);
	if (g->events == NULL) {
		free(g->fds);
		free(g);
		return NULL;
	}
	return g;
}

static int pf_pmu_group_pcore_modify(struct perf_event_attr *a)
{
	(void)a;
	return 0;
}

static int pf_pmu_group_ecore_modify(struct perf_event_attr *a)
{
	bool success;
	uint32_t type;
	uint64_t config;

	success = pf_ecore_type(&type);
	if (!success) {
		return EINVAL;
	}
	success = pf_ecore_config((enum perf_hw_id)a->config, &config);
	if (!success) {
		return EINVAL;
	}
	a->type = type;
	a->config = config;

	return 0;
}

static int pf_open_pmu(struct pf_group *g, struct pf_pmu_group *pmu_g,
		       struct pf_open_args *args, uint32_t pmu, bool is_leader)
{
	int e = 0;
	int groupfd = -1;
	int fd = -1;
	struct perf_event_attr a;
	bool allocated = false;

	if (pmu_g == NULL) {
		pmu_g = pf_pmu_group_allocate(args->grouped);
		if (pmu_g == NULL) {
			e = errno;
			goto error;
		}
		allocated = true;
	}

	pf_open_args_to_perf_event_attr(args, &a, is_leader);

	if (pmu & PF_OPEN_CORES_ECORES) {
		g->ecore = pmu_g;
		e = pf_pmu_group_ecore_modify(&a);
	} else if (pmu & PF_OPEN_CORES_PCORES) {
		g->pcore = pmu_g;
		e = pf_pmu_group_pcore_modify(&a);
	}
	if (e != 0) {
		goto error;
	}

	if (!is_leader && args->grouped) {
		groupfd = pmu_g->fds[0];
	}

	fd = (int)sys_perf_open(&a, 0, -1, groupfd, 0);
	if (fd == -1) {
		e = errno;
		goto error;
	}
	pf_pmu_group_add(pmu_g, fd, args);

	return 0;
error:
	if (allocated) {
		free(pmu_g->fds);
		free(pmu_g->events);
		free(pmu_g);
	}
	return e;
}

struct pf_open_result pf_perf_open(struct pf_open_args *args,
			      struct pf_group *prev_group)
{
	struct perf_event_attr a;
	bool is_leader = false;
	struct pf_group *group = NULL;
	bool group_allocated = false;
	struct pf_open_result res = { EINVAL, NULL };

	if (args->cores == PF_OPEN_CORES_DEFAULT) {
		args->cores = (PF_OPEN_CORES_PCORES | PF_OPEN_CORES_ECORES);
	}

	group = prev_group;
	if (group == NULL) {
		group = malloc(sizeof(*group));
		if (group == NULL) {
			res.error = errno;
			goto error;
		}
		is_leader = true;
		group_allocated = true;
	}

	if (args->cores & PF_OPEN_CORES_PCORES) {
		res.error = pf_open_pmu(group, group->pcore, args,
					PF_OPEN_CORES_PCORES, is_leader);
	}
	if (args->cores & PF_OPEN_CORES_ECORES) {
		res.error = pf_open_pmu(group, group->ecore, args,
					PF_OPEN_CORES_ECORES, is_leader);
	}
	if (res.error != 0) {
		goto error;
	}

	res.error = 0;
	res.group_handle = group;
	return res;

error:
	if (group_allocated == true) {
		free(group);
	}
	res.group_handle = NULL;
	return res;
}

static void pf_pmu_close(struct pf_pmu_group *g)
{
	if (g == NULL) {
		return;
	}
	if (g->fds != NULL) {
		for (unsigned long i = 0; i < g->nopen; ++i) {
			close(g->fds[i]);
		}
		free(g->fds);
	}
	if (g->events != NULL) {
		free(g->events);
	}
	free(g);
}

void pf_perf_close(struct pf_group *g)
{
	pf_pmu_close(g->pcore);
	pf_pmu_close(g->ecore);
	free(g);
}
