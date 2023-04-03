/**
 * @file bench-main.c
 * @author Tend (casablancaernesto@gmail.com)
 * @brief Benchmarking for the signature schemes
 * @version 0.1
 * @date 2023-04-02
 *
 * @copyright Copyright (c) 2023
 */
#include "bench-main.h"

int main(int argc, char *argv[])
{
    setbuf(stdout, NULL);
    pbc_set_msg_to_stderr(0);

    bench_param_t bench_p;
    bench_p->max_samples = DEFAULT_MAX_SAMPLES;
    bench_p->max_sampling_time = DEFAULT_MAX_SAMPLING_TIME;
    bench_p->sec_lvl = DEFAULT_SEC_LVL;
    bench_p->hash_type = DEFAULT_HASH_TYPE;
    unsigned int seed = 0;

    int opt;
    while ((opt = getopt(argc, argv, ":hl:a:t:i:s:")) != -1)
    {
        switch (opt)
        {
        case 'h':
            printf(BENCH_HELP_TOOLTIP, argv[0]);
            exit(EXIT_SUCCESS);
            break;
        case 'l':
            bench_p->sec_lvl = atoi(optarg);
            break;
        case 't':
            bench_p->max_sampling_time = atol(optarg);
            break;
        case 'i':
            bench_p->max_samples = atol(optarg);
            break;
        case 'a':
            if (strcmp(optarg, "sha1") == 0)
                bench_p->hash_type = sha_1;
            else if (strcmp(optarg, "sha256") == 0)
                bench_p->hash_type = sha_256;
            else if (strcmp(optarg, "sha512") == 0)
                bench_p->hash_type = sha_512;
            else
            {
                fprintf(stderr, "%s: Invalid hash type: %s\n", argv[0], optarg);
                exit(EXIT_FAILURE);
            }
            break;
        case 's':
            seed = atoi(optarg);
            break;
        case '?':
            fprintf(stderr, "%s: Unexpected option: %c\n", argv[0], optopt);
            exit(EXIT_FAILURE);
        case ':':
            fprintf(stderr, "%s: Missing value for: %c\n", argv[0], optopt);
            exit(EXIT_FAILURE);
        default:
            fprintf(stderr, BENCH_USAGE, argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    printf_params(bench_p);

    printf("Calibration timing functions...\n");
    calibrate_timing_methods();

    if (seed > 0)
    {
        printf("Using random seed: %d\n", seed);
        pbc_random_set_deterministic((unsigned int)seed);
    }

    printf("Benchmarking...\n");

    bench_shared(bench_p);
    bench_sv(bench_p);
    bench_imp_sv(bench_p);
    return 0;
}

void printf_params(bench_param_t bench_p)
{
    printf(SEPARATOR);
    printf("Benchmark parameters:\n");
    printf("\tMax samples: %ld\n", bench_p->max_samples);
    printf("\tMax sampling time: %ld\n", bench_p->max_sampling_time);
    printf("\tSecurity level: %d\n", bench_p->sec_lvl);
    printf("\tHash type: %s\n", bench_p->hash_type == sha_1 ? "sha1" : bench_p->hash_type == sha_256 ? "sha256"
                                                                                                     : "sha512");
    printf(SEPARATOR);
}