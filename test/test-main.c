#include "test-main.h"

int main()
{
    Suite *(*suite_creators[NSUITE])(void) = {utility_suite, data_suite, sv_scheme_suite, imp_sv_scheme_suite};

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