/**
 * @file main.h
 * @author TendTo (https://github.com/TendTo)
 *
 * @brief Main file header
 * The execution of the application starts here
 */

#ifndef MAIN_H
#define MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C"
{
#endif

#include "define.h"
#include "sv-scheme.h"
#include "imp-sv-scheme.h"
#include "shared.h"

#define PARAMS_ERROR(expected, actual, argv)                                   \
    if (actual < expected)                                                     \
    {                                                                          \
        fprintf(stderr, "Expected %d parameters, got %d\n", expected, actual); \
        fprintf(stderr, USAGE, argv[0]);                                       \
        exit(EXIT_FAILURE);                                                    \
    }

#ifdef __cplusplus
}
#endif

#endif