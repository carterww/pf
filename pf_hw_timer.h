#ifndef PF_HW_TIMER_H
#define PF_HW_TIMER_H

#define _POSIX_C_SOURCE 199309L

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include <sys/time.h>

/* TODO: Fetch this dynamically */
#define PF_TSC_FREQ_HZ_INTEL_12700K (3609000000.6)

struct pf_hw_timer {
	uint64_t start;
	struct timespec duration;
};

struct pf_time_suffix_entry {
	const char *const name;
	size_t length;
};

enum pf_hw_timer_units {
	PF_HW_TIMER_SEC = 0,
	PF_HW_TIMER_MS,
	PF_HW_TIMER_US,
	PF_HW_TIMER_NS,
	PF_HW_TIMER_OOR,
};

extern const struct pf_time_suffix_entry PF_HW_TIMER_UNIT_SUFFIX[];
extern const uint64_t PF_HW_TIMER_UNIT_SEC_CONV[];
extern const double PF_HW_TIMER_UNIT_SEC_CONV_DOUBLE[];

extern const size_t PF_HW_TIMER_UNIT_SUFFIX_LENGTH;
extern const size_t PF_HW_TIMER_UNIT_SEC_CONV_LENGTH;
extern const size_t PF_HW_TIMER_UNIT_SEC_CONV_DOUBLE_LENGTH;

#if defined(__amd64__) || defined(__x86_64__)
inline static uint64_t pf_hw_tsc_read(void)
{
	uint64_t val;
	/* Execute an mfence prior to this if your benchmarking required all stores
	 * to be globally visible before executing.
	 *
	 * rdtscp reads the TSC counter into EDX:EAX and the AUX_MSR into ECX. I won't
	 * use AUX_MSR but this instruction serializes prior instructions unlike rdtsc.
	 *
	 * An lfence is required after rdtscp to ensure no instructions are executed until
	 * rdtsc is actually read.
	 */
	__asm__ __volatile__("rdtscp\n"
			     "lfence\n"
			     "shl rdx, 32\n"
			     "or rax, rdx\n"
			     : "=a"(val)
			     :
			     : "rdx", "ecx", "memory");

	return val;
}
#endif /* x86_64 */

inline static void pf_hw_timer_tsc_to_timespec(uint64_t tsc, double tsc_freq_hz,
					       struct timespec *t)
{
	double tsc_d = (double)tsc;
	double ns_d = tsc_d * (1e9 / tsc_freq_hz);

	uint64_t ns = (uint64_t)(ns_d + 0.5);
	t->tv_sec = ns / 1000000000;
	t->tv_nsec = ns % 1000000000;
}

inline static void pf_hw_timer_start(struct pf_hw_timer *t)
{
	t->start = pf_hw_tsc_read();
}

/* To retrieve the tsc_freq you can search dmesg for messages like:
 * [    0.000000] tsc: Detected 3600.000 MHz processor
 * [    0.000000] tsc: Detected 3609.600 MHz TSC
 *
 * Then use this value. There's no nontrivial way to get this so I'm just going
 * to hardcode it for now.
 *
 * WARNING: This hw_timer code for x86 assumes your processor supports constant_tsc.
 * If not, different cores can run at different tsc frequencies which can result in
 * erroneous results if your thread is migrated to another core between start and end.
 */
inline static void pf_hw_timer_end(struct pf_hw_timer *t, double tsc_freq_hz)
{
	uint64_t end;
	uint64_t tsc_duration;

	end = pf_hw_tsc_read();
	tsc_duration = end - t->start;
	pf_hw_timer_tsc_to_timespec(tsc_duration, tsc_freq_hz, &t->duration);
}

inline static uint64_t pf_timer_timespec_to_unit(const struct timespec *t,
						 enum pf_hw_timer_units unit)
{
	uint64_t s;
	uint64_t ns;
	enum pf_hw_timer_units last = PF_HW_TIMER_OOR - 1;

	if (t->tv_sec < 0 || t->tv_nsec < 0) {
		return 0;
	}
	s = (uint64_t)t->tv_sec;
	ns = (uint64_t)t->tv_nsec;

	return s * PF_HW_TIMER_UNIT_SEC_CONV[unit] +
	       ns / PF_HW_TIMER_UNIT_SEC_CONV[last - unit];
}

inline static double
pf_timer_timespec_to_unit_double(const struct timespec *t,
				 enum pf_hw_timer_units unit)
{
	double s;
	double ns;
	enum pf_hw_timer_units last = PF_HW_TIMER_OOR - 1;

	if (t->tv_sec < 0 || t->tv_nsec < 0) {
		return 0;
	}
	s = (double)t->tv_sec;
	ns = (double)t->tv_nsec;

	return s * PF_HW_TIMER_UNIT_SEC_CONV_DOUBLE[unit] +
	       ns / PF_HW_TIMER_UNIT_SEC_CONV_DOUBLE[last - unit];
}

inline static uint64_t _pf_timer_log10_approx_overestimate(uint64_t val)
{
	static const uint64_t log2_log10_scale = 1000000;
	static const uint64_t log2_log10_den = 301030;
	uint64_t log2_ceil;

	val += 1; /* bsr has undefined result if source is 0 */

	__asm__ __volatile__("bsr %0, %1" : "=r"(log2_ceil) : "r"(val) :);
	log2_ceil += (val & (val - 1)) != 0;

	return ((log2_ceil * log2_log10_den) / log2_log10_scale);
}

inline static size_t
pf_timer_pretty_time_buffer_len(const struct timespec *t,
				enum pf_hw_timer_units unit,
				unsigned int frac_precision)
{
	uint64_t time;

	size_t rb = 0;
	rb += PF_HW_TIMER_UNIT_SUFFIX[unit].length;
	if (frac_precision > 0) {
		rb += frac_precision + 1;
	}

	time = pf_timer_timespec_to_unit(t, unit);
	rb += _pf_timer_log10_approx_overestimate(time) + 1;

	return rb;
}

inline static bool pf_timer_pretty_time(const struct timespec *t,
					enum pf_hw_timer_units unit,
					unsigned int frac_precision, char *buf,
					size_t buf_len)
{
	size_t n;
	double time;

	time = pf_timer_timespec_to_unit_double(t, unit);
	if (frac_precision == 0) {
		uint64_t whole;
		whole = (uint64_t)time;
		n = (size_t)snprintf(buf, buf_len, "%lu%s", whole,
				     PF_HW_TIMER_UNIT_SUFFIX[unit].name);
	} else {
		n = (size_t)snprintf(buf, buf_len, "%.*f%s", frac_precision,
				     time, PF_HW_TIMER_UNIT_SUFFIX[unit].name);
	}
	/* snprintf doesn't include '\0' in number of intended bytes written to
	 * buf. If n == buf_len then one character was truncated for '\0'.
	 */
	return buf_len > n;
}

#endif /* PF_HW_TIMER_H */
