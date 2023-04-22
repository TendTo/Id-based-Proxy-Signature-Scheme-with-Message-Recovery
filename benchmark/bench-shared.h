/**
 * @file bench-shared.h
 * @author TendTo (https://github.com/TendTo)
 *
 * @brief Benchmark the functions used in both schemes
 */
#ifndef BENCH_SHARED_H
#define BENCH_SHARED_H

#include <pbc/pbc.h>
#include "lib-timing.h"
#include "shared.h"
#include "bench-const.h"

void bench_shared(bench_param_t bench_p);

#endif // BENCH_SHARED_H
