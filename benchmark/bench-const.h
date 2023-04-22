#ifndef BENCH_CONST_H
#define BENCH_CONST_H

#include "lib-timing.h"
#include "shared.h"

#define SEPARATOR "---------------------------------------------------------------------\n"

// Usage tooltip
#define BENCH_USAGE \
    "Usage: %s [options] \n\
Use -h to know more informations\n"

// Help tooltip
#define BENCH_HELP_TOOLTIP \
    "" SEPARATOR "\
" PROJECT_NAME " benchmarks, version " VERSION "\n\
Usage: %s \n\
" SEPARATOR "\
Options:\n\
\t-h   -  shows the help tooltip\n\
\t-v   -  use verbose output\n\
\t-a   -  hash algorithm [sha1, sha256, sha512] (sha1)\n\
\t-l   -  security level (80)\n\
\t-t   -  maximum sampling time in seconds (4)\n\
\t-i   -  maximum number of samples (4000)\n\
\t-s   -  if set, use the seed for random functions\n"

struct bench_param_struct
{
    elapsed_time_t time;
    stats_t bench_stats;
    size_t max_samples;
    long max_sampling_time;
    int sec_lvl;
    hash_type_t hash_type;
};
typedef struct bench_param_struct *bench_param_ptr;
typedef struct bench_param_struct bench_param_t[1];

#endif // BENCH_CONST_H