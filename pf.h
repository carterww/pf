#ifndef PF_H
#define PF_H

#include <pf_hw_timer.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include <linux/perf_event.h>
#include <sys/ioctl.h>

#define PF_IOCTL_FLAG(g) ((g)->nopen > 1 ? PERF_IOC_FLAG_GROUP : 0)

#define PF_OPEN_CORES_DEFAULT (0)
#define PF_OPEN_CORES_PCORES ((uint32_t)1 << 0)
#define PF_OPEN_CORES_ECORES ((uint32_t)1 << 1)

union pf_type_specific {
	enum perf_hw_id hw;
	enum perf_sw_ids sw;
	struct {
		enum perf_hw_cache_id id;
		enum perf_hw_cache_op_id op;
		enum perf_hw_cache_op_result_id op_result;
	} cache;
};

struct pf_open_args {
	enum perf_type_id type;
	union pf_type_specific type_specific;
	uint32_t cores;
	bool grouped;
	bool exclude_user;
	bool exclude_kernel;
	bool exclude_hypervisor;
	bool exclude_idle;
};

struct pf_pmu_group {
	unsigned long nopen;
	unsigned long cap;
	int *fds;
	struct pf_open_args *events;
};

struct pf_group {
	struct pf_pmu_group *pcore;
	struct pf_pmu_group *ecore;
};

struct pf_pmu_group_result {
	uint64_t nr;
	uint64_t vals[];
};

struct pf_group_result {
	struct pf_pmu_group_result *pcore;
	struct pf_pmu_group_result *ecore;
};

struct pf_open_result {
	int error;
	struct pf_group *group_handle;
};

extern const char *const PF_PERF_TYPE_HW_NAMES[];
extern const char *const PF_PERF_TYPE_SW_NAMES[];
extern const char *const PF_PERF_TYPE_CACHE_NAMES[];
extern const char *const PF_PERF_TYPE_CACHE_OP_NAMES[];
extern const char *const PF_PERF_TYPE_CACHE_OP_RESULT_NAMES[];

extern const size_t PF_PERF_TYPE_HW_NAMES_LENGTH;
extern const size_t PF_PERF_TYPE_SW_NAMES_LENGTH;
extern const size_t PF_PERF_TYPE_CACHE_NAMES_LENGTH;
extern const size_t PF_PERF_TYPE_CACHE_OP_NAMES_LENGTH;
extern const size_t PF_PERF_TYPE_CACHE_OP_RESULT_NAMES_LENGTH;

inline static struct pf_pmu_group_result *
pf_pmu_result_read(const struct pf_pmu_group *g)
{
	struct pf_pmu_group_result *res;
	uint64_t vals_size;

	if (g == NULL || g->nopen == 0) {
		return NULL;
	}
	if (g->nopen == 1) {
		vals_size = sizeof(uint64_t) * g->nopen;
	} else {
		vals_size = sizeof(uint64_t) * (1 + g->nopen);
	}
	res = malloc(sizeof(*res) + vals_size);
	if (res == NULL) {
		return NULL;
	}
	res->nr = g->nopen;

	uint64_t *vals = malloc(vals_size);
	if (vals == NULL) {
		return NULL;
	}
	if (read(g->fds[0], vals, vals_size) == -1) {
		free(vals);
		return NULL;
	}
	if (g->nopen == 1) {
		for (uint64_t i = 0; i < res->nr; ++i) {
			res->vals[i] = vals[i];
		}
	} else {
		for (uint64_t i = 0; i < res->nr; ++i) {
			res->vals[i] = vals[i + 1];
		}
	}

	free(vals);
	return res;
}

inline static struct pf_group_result *pf_result_read(const struct pf_group *g)
{
	struct pf_group_result *res;
	uint64_t vals_size;

	res = malloc(sizeof(*res));
	if (res == NULL) {
		return NULL;
	}
	if (g->pcore != NULL) {
		res->pcore = pf_pmu_result_read(g->pcore);
		if (res->pcore == NULL) {
			free(res);
			return NULL;
		}
	}
	if (g->ecore != NULL) {
		res->ecore = pf_pmu_result_read(g->ecore);
		if (res->ecore == NULL) {
			free(res->pcore);
			free(res);
			return NULL;
		}
	}

	return res;
}

inline static void pf_pmu_result_free(struct pf_pmu_group_result *r)
{
	free(r);
}

inline static void pf_result_free(struct pf_group_result *r)
{
	if (r->pcore != NULL) {
		pf_pmu_result_free(r->pcore);
	}
	if (r->ecore != NULL) {
		pf_pmu_result_free(r->ecore);
	}
	free(r);
}

inline static void pf_ioctl(const struct pf_pmu_group *g, unsigned int op)
{
	ioctl(g->fds[0], op, PF_IOCTL_FLAG(g));
}

inline static void pf_reset(const struct pf_group *g)
{
	if (g->pcore != NULL) {
		pf_ioctl(g->pcore, PERF_EVENT_IOC_RESET);
	}
	if (g->ecore != NULL) {
		pf_ioctl(g->ecore, PERF_EVENT_IOC_RESET);
	}
}

inline static void pf_resume(const struct pf_group *g)
{
	if (g->pcore != NULL) {
		pf_ioctl(g->pcore, PERF_EVENT_IOC_ENABLE);
	}
	if (g->ecore != NULL) {
		pf_ioctl(g->ecore, PERF_EVENT_IOC_ENABLE);
	}
}

inline static void pf_pause(const struct pf_group *g)
{
	if (g->pcore != NULL) {
		pf_ioctl(g->pcore, PERF_EVENT_IOC_DISABLE);
	}
	if (g->ecore != NULL) {
		pf_ioctl(g->ecore, PERF_EVENT_IOC_DISABLE);
	}
}

inline static void pf_start(const struct pf_group *g)
{
	pf_reset(g);
	pf_resume(g);
}

inline static struct pf_group_result *pf_stop(const struct pf_group *g)
{
	pf_pause(g);
	return pf_result_read(g);
}

struct pf_open_result pf_perf_open(struct pf_open_args *args,
				   struct pf_group *prev_group);
void pf_perf_close(struct pf_group *g);

#undef PF_IOCTL_FLAG
#endif /* PH_H */
