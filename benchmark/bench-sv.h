#ifndef BENCH_SV_H
#define BENCH_SV_H

#include <pbc/pbc.h>
#include "lib-timing.h"
#include "sv-scheme.h"
#include "bench-const.h"

void bench_setup(bench_param_t bench_p);
void bench_extract_p(bench_param_t bench_p);
void bench_extract_s(bench_param_t bench_p);
void bench_delegate(bench_param_t bench_p);
void bench_del_verify(bench_param_t bench_p);


#endif // BENCH_SV_H
