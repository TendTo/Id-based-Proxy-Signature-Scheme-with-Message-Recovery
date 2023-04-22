#ifndef BENCH_MAIN_H
#define BENCH_MAIN_H

#include <stdio.h>
#include <getopt.h>
#include "bench-const.h"
#include "bench-sv.h"
#include "bench-imp-sv.h"
#include "bench-shared.h"

#define DEFAULT_SEC_LVL 80
#define DEFAULT_MAX_SAMPLING_TIME 4
#define DEFAULT_MAX_SAMPLES (DEFAULT_MAX_SAMPLING_TIME * 1000)
#define DEFAULT_HASH_TYPE sha_1
#define DEFAULT_PRECOMPUTE 0

void printf_params(bench_param_t bench_p);
int main(int argc, char *argv[]);

#endif // BENCH_MAIN_H