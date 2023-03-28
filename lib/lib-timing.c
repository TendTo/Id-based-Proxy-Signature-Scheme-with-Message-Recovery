/*
 *  Copyright 2021 Mario Di Raimondo <diraimondo@dmi.unict.it>
 *
 *  This source code is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This source code is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * libreria per il campionamento preciso del timing attraverso varie chiamate di
 * sistema (POSIX e non) e attraverso l'uso del contatore Intel TSC
 */

#include "lib-timing.h"

float stats_kernel_lower_cut = 0.005, stats_kernel_upper_cut = 0.05;
double clock_cycles_per_ns = 1.0;
elapsed_time_t clock_cycles_timing_overhead = 0.0;
elapsed_time_t timestamp_timing_overhead = 0.0;
const char *time_unit_str[] = {"ns", "μs", "ms", "s"};
#define calibration_loop 1000000

/* cerca di rilevare i metodi di timestamp disponibili sul sistema;
 * in tale scelta si prediligono i metodi che misurano il tempo di CPU
 * eventualmente a discapito della precisione
 */
#if defined(__MACH__)
clockid_t clock_to_use = CLOCK_GETRUSAGE_ID;
#elif defined(__linux__)
#if defined(_POSIX_CPUTIME)
// clockid_t clock_to_use = CLOCK_PROCESS_CPUTIME_ID;
clockid_t clock_to_use = CLOCK_THREAD_CPUTIME_ID;
#else
clockid_t clock_to_use = CLOCK_MONOTONIC;
#warning                                                                       \
    "can't find a method to access the CPU time: reverting on CLOCK_MONOTONIC method"
#endif /* defined(_POSIX_CPUTIME) */
#elif defined(_WIN32)
clockid_t clock_to_use = CLOCK_PROCESS_TIME_WIN_ID;
#else
#warning "no suitable clock timer for this system: timing will not work!"
clockid_t clock_to_use = CLOCK_NONE;
#endif

/* utilizza il supporto all'istruzione 'rdtscp' solo se specificato dal Makefile
 */
#ifdef USE_RDTSCP
clock_cycles_t (*get_clock_cycles_before)() = &cpuid_rdtsc;
clock_cycles_t (*get_clock_cycles_after)() = &rdtscp_cpuid;
#else
clock_cycles_t (*get_clock_cycles_before)() = &cpuid_rdtsc;
clock_cycles_t (*get_clock_cycles_after)() = &cpuid_rdtsc;
#endif /* USE_RDTSCP */

/* codice assembly per Intel 64 e 32 bit per la lettura di TSC */
#ifdef __x86_64__ /* codice assembly x86_64 */
inline clock_cycles_t rdtsc() {
    unsigned int lo, hi;
    asm volatile("rdtsc ;"
                 "mov %%edx, %0 ;"
                 "mov %%eax, %1 ;"
                 : "=r"(hi), "=r"(lo)
                 :
                 : "%rax", "%rdx");
    return ((unsigned long long)lo) | (((unsigned long long)hi) << 32);
}

inline clock_cycles_t cpuid_rdtsc() {
    unsigned int lo, hi;
    asm volatile("cpuid ;"
                 "rdtsc ;"
                 "mov %%edx, %0 ;"
                 "mov %%eax, %1 ;"
                 : "=r"(hi), "=r"(lo)
                 :
                 : "%rax", "%rbx", "%rcx", "%rdx");
    return ((unsigned long long)lo) | (((unsigned long long)hi) << 32);
}

inline clock_cycles_t rdtscp() {
    unsigned int lo, hi;
    asm volatile("rdtscp ;"
                 "mov %%edx, %0 ;"
                 "mov %%eax, %1 ;"
                 : "=r"(hi), "=r"(lo)
                 :
                 : "%rax", "%rcx", "%rdx");
    return ((unsigned long long)lo) | (((unsigned long long)hi) << 32);
}

inline clock_cycles_t rdtscp_cpuid() {
    unsigned int lo, hi;
    asm volatile("rdtscp ;"
                 "mov %%edx, %0 ;"
                 "mov %%eax, %1 ;"
                 "cpuid ;"
                 : "=r"(hi), "=r"(lo)
                 :
                 : "%rax", "%rbx", "%rcx", "%rdx");
    return ((unsigned long long)lo) | (((unsigned long long)hi) << 32);
}
#else  /* codice assembly i386 */
inline clock_cycles_t rdtsc() {
    unsigned int lo, hi;
    asm volatile("rdtsc ;"
                 "mov %%edx, %0 ;"
                 "mov %%eax, %1 ;"
                 : "=r"(hi), "=r"(lo)
                 :
                 : "%eax", "%edx");
    return ((unsigned long long)lo) | (((unsigned long long)hi) << 32);
}

inline clock_cycles_t cpuid_rdtsc() {
    unsigned int lo, hi;
    asm volatile("cpuid ;"
                 "rdtsc ;"
                 "mov %%edx, %0 ;"
                 "mov %%eax, %1 ;"
                 : "=r"(hi), "=r"(lo)
                 :
                 : "%eax", "%ebx", "%ecx", "%edx");
    return ((unsigned long long)lo) | (((unsigned long long)hi) << 32);
}

inline clock_cycles_t rdtscp() {
    unsigned int lo, hi;
    asm volatile("rdtscp ;"
                 "mov %%edx, %0 ;"
                 "mov %%eax, %1 ;"
                 : "=r"(hi), "=r"(lo)
                 :
                 : "%eax", "%ecx", "%edx");
    return ((unsigned long long)lo) | (((unsigned long long)hi) << 32);
}

inline clock_cycles_t rdtscp_cpuid() {
    unsigned int lo, hi;
    asm volatile("rdtscp ;"
                 "mov %%edx, %0 ;"
                 "mov %%eax, %1 ;"
                 "cpuid ;"
                 : "=r"(hi), "=r"(lo)
                 :
                 : "%eax", "%ebx", "%ecx", "%edx");
    return ((unsigned long long)lo) | (((unsigned long long)hi) << 32);
}
#endif /* __x86_64__ */

/* ottiene il timestamp attuale con il metodo preconfigurato */
inline void get_timestamp(timestamp_t ts) {
#if defined(__MACH__)
    static bool mac_services_initialized = false;
    static clock_serv_t cclock;
    static mach_timebase_info_data_t timebase_info;
    if (!mac_services_initialized) {
        host_get_clock_service(mach_host_self(), MAC_CLOCK_SERVICE_TO_USE,
                               &cclock);
        // mach_port_deallocate(mach_task_self(), cclock); // mai disallocato
        mach_timebase_info(&timebase_info);
        mac_services_initialized = true;
    }
    if (clock_to_use == (clockid_t)CLOCK_ABSTIME_MAC_ID) {
        assert(timebase_info.denom);
        double mts = (mach_absolute_time() * timebase_info.numer) /
                     (double)timebase_info.denom;
        ts->tv_sec = mts * 1e-9;
        ts->tv_nsec = mts - (ts->tv_sec * 1e+9);
        return;
    } else if (clock_to_use == (clockid_t)CLOCK_SERVICE_MAC_ID) {
        mach_timespec_t mts;
        clock_get_time(cclock, &mts);
        ts->tv_sec = mts.tv_sec;
        ts->tv_nsec = mts.tv_nsec;
        return;
    }
#endif /* defined(__MACH__) */

#if defined(_WIN32)
    static bool win_clock_initialized = false;
    static LARGE_INTEGER counter_frequency;
    static HANDLE handle;
    if (!win_clock_initialized) {
        QueryPerformanceFrequency(&counter_frequency);
        handle = GetCurrentProcess();
        win_clock_initialized = true;
    }
    if (clock_to_use == (clockid_t)CLOCK_QPC_WIN_ID) {
        assert(counter_frequency.QuadPart > 0);
        LARGE_INTEGER pc;
        QueryPerformanceCounter(&pc);
        double wts = pc.QuadPart * 1e+9 / (double)counter_frequency.QuadPart;
        ts->tv_sec = wts * 1e-9;
        ts->tv_nsec = wts - (ts->tv_sec * 1e+9);
        return;
    } else if (clock_to_use == (clockid_t)CLOCK_PROCESS_TIME_WIN_ID) {
        LARGE_INTEGER dummy_time, user_time;
        GetProcessTimes(handle, (FILETIME *)&dummy_time,
                        (FILETIME *)&dummy_time, (FILETIME *)&dummy_time,
                        (FILETIME *)&user_time);
        ts->tv_sec = user_time.QuadPart * 1e+2 * 1e-9;
        ts->tv_nsec = user_time.QuadPart * 1e+2 - (ts->tv_sec * 1e+9);
        return;
    }
#endif /* defined(_WIN32) */

#if defined(__unix__)
    if (clock_to_use == (clockid_t)CLOCK_GETRUSAGE_ID) {
        struct rusage res;
        getrusage(RUSAGE_SELF, &res);
        ts->tv_sec = res.ru_utime.tv_sec;
        ts->tv_nsec = res.ru_utime.tv_usec * 1e+3;
        return;
    }
#endif /* defined(__unix__) */

    if (clock_to_use != (clockid_t)CLOCK_NONE)
        clock_gettime(clock_to_use, ts);
    else {
        ts->tv_sec = 0;
        ts->tv_nsec = 0;
    }
}

/* rileva la risoluzione in ns del metodo di timestamp preconfigurato */
elapsed_time_t get_timestamp_resolution() {
#if defined(__MACH__)
    if (clock_to_use == (clockid_t)CLOCK_ABSTIME_MAC_ID) {
        return 1.0; /* la documentazione riporta una risoluzine di 1 ns */
    } else if (clock_to_use == (clockid_t)CLOCK_SERVICE_MAC_ID) {
        clock_serv_t cclock;
        natural_t attribute[4];
        mach_msg_type_number_t count = sizeof(attribute) / sizeof(natural_t);
        host_get_clock_service(mach_host_self(), MAC_CLOCK_SERVICE_TO_USE,
                               &cclock);
        clock_get_attributes(cclock, CLOCK_GET_TIME_RES,
                             (clock_attr_t)&attribute, &count);
        mach_port_deallocate(mach_task_self(), cclock);
        return (elapsed_time_t)attribute[0];
    }
#endif /* defined(__MACH__) */

#if defined(_WIN32)
    if (clock_to_use == (clockid_t)CLOCK_QPC_WIN_ID) {
        LARGE_INTEGER counter_frequency;
        QueryPerformanceFrequency(&counter_frequency);
        return (1e+9 / (double)counter_frequency.QuadPart);
    } else if (clock_to_use == (clockid_t)CLOCK_PROCESS_TIME_WIN_ID) {
        return 1e+2; /* la documentazione riporta una risoluzione di 100 ns */
    }
#endif /* defined(_WIN32) */

    /* metodi POSIX */
    if (clock_to_use == (clockid_t)CLOCK_GETRUSAGE_ID) {
/* risoluzioni raccolta da vari tipi di documentazione */
#if defined(__MACH__)
        return 1e+3; /* risoluzione di 1 µs su Mac */
#endif
#if defined(__linux__)
        return 1e+6; /* risoluzione di 1 ms su Linux */
#endif
        return 0.0;
    }
    if (clock_to_use != (clockid_t)CLOCK_NONE) {
        timestamp_t res;
        clock_getres(clock_to_use, res);
        return (res->tv_sec * 1e+9) + (res->tv_nsec);
    } else
        return 0.0;
}

/* calcola il tempo trascorso (ns) tra due campionamenti tramite il metodo
 * timestamp, tenendo eventualmente conto dell'overhead */
elapsed_time_t get_elapsed_time_from_timestamp(timestamp_t before,
                                               timestamp_t after) {
    long long deltat_s = after->tv_sec - before->tv_sec;
    long long deltat_ns = after->tv_nsec - before->tv_nsec;
    return deltat_s * 1e+9 + deltat_ns - timestamp_timing_overhead;
}

/* imposta i tagli statistici (basso e alto) all'insieme dei sample rilevati */
void set_stats_kernel_cuts(float lower, float upper) {
    stats_kernel_lower_cut = lower;
    stats_kernel_upper_cut = upper;
}

/* scrive direttamente e legge il rapporto cicli/ns preconfigurato */
void set_clock_cycles_per_ns(double ratio) { clock_cycles_per_ns = ratio; }
elapsed_time_t get_clock_cycles_per_ns() { return clock_cycles_per_ns; }

/* calibra la precisione dei metodi impiegati: attualmente rileva
 * automaticamente il rapporto cicli/ns sull'attuale macchina e i vari overhead
 * di misurazione */
void calibrate_timing_methods() {
    timestamp_t before_ts, after_ts;
    clock_cycles_t before = 0, after = 0;
    clockid_t old_clock_to_use = clock_to_use;

/* seleziona un metodo NON basato sul tempo di CPU */
#if defined(__linux__)
    clock_to_use = CLOCK_MONOTONIC;
#elif defined(__MACH__)
    clock_to_use = CLOCK_ABSTIME_MAC_ID;
#else
    clock_to_use = CLOCK_QPC_WIN_ID;
#endif /* defined(__MACH__) ; defined(__linux__) */

    get_timestamp(before_ts);
    before = get_clock_cycles_before();
    for (volatile unsigned long long i = 0; i < calibration_loop; i++)
        ;
    after = get_clock_cycles_after();
    get_timestamp(after_ts);
    clock_cycles_per_ns =
        (double)(after - before) /
        (double)get_elapsed_time_from_timestamp(before_ts, after_ts);

    clock_to_use = old_clock_to_use;

    detect_clock_cycles_overhead();
    detect_timestamp_overhead();
}

/* legge il valore di overhead attualmente configurato per il metodo basato su
 * clock cycles */
elapsed_time_t get_clock_cycles_overhead() {
    return clock_cycles_timing_overhead;
}

/* rileva automaticamente l'overhead caratterizzante il metodo basato su clock
 * cycles */
void detect_clock_cycles_overhead() {
    stats_t stats;
    perform_wc_time_sampling(stats, NULL, calibration_loop, tu_nanos, {}, {});
    clock_cycles_timing_overhead = stats->median;
}

/* legge il valore di overhead attualmente configurato per il metodo timestamp
 */
elapsed_time_t get_timestamp_overhead() { return timestamp_timing_overhead; }

/* rileva automaticamente l'overhead caratterizzante il metodo timestamp
 * preconfigurato */
void detect_timestamp_overhead() {
    stats_t stats;
    perform_cpu_time_sampling(stats, NULL, calibration_loop, tu_nanos, {}, {});
    timestamp_timing_overhead = stats->median;
}

/* calcola il tempo trascorso (ns) tra due campionamenti tramite il metodo
 * basato su clock cycles, tenendo conto del rapporto cicli/ns rilevato ed,
 * eventualmente, dell'overhead */
inline elapsed_time_t get_elapsed_time_from_cpu_cycles(clock_cycles_t before,
                                                       clock_cycles_t after) {
    return rintl(((after - before) / clock_cycles_per_ns) -
                 clock_cycles_timing_overhead);
}

/* converte un tempo rilevato (ns) in una specifica unità di tempo */
inline elapsed_time_t et_to(const elapsed_time_t ns, enum time_unit unit) {
    return ns / pow(10.0, unit * 3);
}

/* confronta due rilevamenti */
static int __et_compare(const void *n1, const void *n2) {
    if (*(elapsed_time_t *)n1 > *(elapsed_time_t *)n2)
        return 1;
    else if (*(elapsed_time_t *)n1 < *(elapsed_time_t *)n2)
        return -1;
    else
        return 0;
}

/* calcola vari indici statistici sull'insieme di rilevamenti disponibili */
void extract_stats(stats_t stats, elapsed_time_t vector[], size_t size,
                   enum time_unit unit) {
    elapsed_time_t sum = 0.0;
    size_t i, first;

    assert(stats);
    assert(size >= 1);

    if (size == 1) {
        stats->unit = unit;
        stats->size = stats->ksize = size;
        stats->min = stats->max = stats->median = stats->mean = vector[0];
        stats->stddev = 0.0;
        return;
    }

    stats->unit = unit;
    stats->size = size;
    stats->ksize = (size_t)ceilf(
        size * (1.0 - stats_kernel_lower_cut - stats_kernel_upper_cut));

    qsort(vector, size, sizeof(elapsed_time_t), __et_compare);

    first = (size_t)ceilf(size * stats_kernel_lower_cut);

    stats->max = vector[stats->ksize - 1];
    stats->min = vector[first];

    if (stats->ksize % 2)
        stats->median = vector[first + (stats->ksize / 2)];
    else
        stats->median = (vector[first + (stats->ksize / 2 - 1)] +
                         vector[first + (stats->ksize / 2)]) /
                        2.0;

    for (i = first; i < stats->ksize + first; i++)
        sum += vector[i];
    stats->mean = sum / stats->ksize;

    stats->stddev = 0.0;
    for (i = first; i < stats->ksize + first; i++) {
        stats->stddev += pow(vector[i] - stats->mean, 2);
    }

    stats->stddev = sqrt(stats->stddev / stats->ksize);
}

/* manda su uno stream un singolo valore statistico tenendo conto dell'unità di
 * misura prescelta e della sua precisione */
inline void fprintf_et(FILE *stream, const char *prefix,
                       const elapsed_time_t number, enum time_unit unit,
                       const char *suffix) {
    fprintf(stream, "%s%.*lf %s%s", prefix, unit * 3, number,
            time_unit_str[unit], suffix);
}

/* manda su uno stream tutti gli indici statistici disponibili su un insieme di
 * rilevamenti */
void fprintf_stats(FILE *stream, const char *name, const stats_t stats,
                   const char *suffix) {
    fprintf(stream, "%s:", name);
    fprintf_et(stream, " media=", stats->mean, stats->unit, "");
    fprintf_et(stream, ", mediana=", stats->median, stats->unit, "");
    fprintf(stream, ", dev.st.=%.*lf %s",
            (stats->unit <= tu_micros ? tu_micros : stats->unit) * 3,
            stats->stddev, time_unit_str[stats->unit]);
    fprintf_et(stream, ", min=", stats->min, stats->unit, "");
    fprintf_et(stream, ", max=", stats->max, stats->unit, "");
    fprintf(stream, ", kernel=%zd/%zd%s\n", stats->ksize, stats->size, suffix);
}

/* manda su uno stream solo mediana e deviazione standard relativi all'insieme
 * di rilevamenti */
void fprintf_short_stats(FILE *stream, const char *name, const stats_t stats,
                         const char *suffix) {
    if (strlen(name) > 0)
        fprintf(stream, "%s: ", name);
    fprintf_et(stream, "", stats->median, stats->unit, "");
    if (stats->stddev > 0.0)
        fprintf(stream, " (±%.*lf %s)%s\n",
                (stats->unit <= tu_micros ? tu_micros : stats->unit) * 3,
                stats->stddev, time_unit_str[stats->unit], suffix);
    else
        fprintf(stream, "%s\n", suffix);
}
