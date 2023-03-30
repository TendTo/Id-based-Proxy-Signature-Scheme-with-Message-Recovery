#include <check.h>
#include "test-const.h"
#include "test-shared.h"
#include "test-sv-scheme.h"

#define NSUITE 2

int main()
{
    Suite *(*suite_creators[NSUITE])(void) = {utility_suite, sv_scheme_suite};

    int no_failed = 0;
    Suite *s;
    SRunner *runner;

    for (size_t i = 0; i < NSUITE; ++i)
    {
        s = suite_creators[i]();
        runner = srunner_create(s);

        srunner_run_all(runner, CK_NORMAL);
        no_failed += srunner_ntests_failed(runner);
        srunner_free(runner);
    }

    return no_failed;
}