#include "main.h"

int main(int argc, char *argv[])
{
    int opt;

    // Handle inputs
    while ((opt = getopt(argc, argv, ":h")) != -1)
    {
        switch (opt)
        {
        case 'h':
            printf(HELP_TOOLTIP, argv[0]);
            exit(EXIT_SUCCESS);
            break;
        case '?':
            fprintf(stderr, "%s: Unexpected option: %c\n", argv[0], optopt);
            exit(EXIT_FAILURE);
        case ':':
            fprintf(stderr, "%s: Missing value for: %c\n", argv[0], optopt);
            exit(EXIT_FAILURE);
        default:
            fprintf(stderr, USAGE, argv[0]);
            exit(EXIT_FAILURE);
        }
    }
    if (optind != argc - 2)
    {
        fprintf(stderr, USAGE, argv[0]);
        exit(EXIT_FAILURE);
    }

    return 0;
}