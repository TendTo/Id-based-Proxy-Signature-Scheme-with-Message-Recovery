#include <check.h>
#include "shared.h"

START_TEST(test_swap)
{
    double A[2] = {1.0, 2.0};
    ck_assert(A[1] - 2.0 < 0.00001);
    ck_assert(A[1] - 2.0 > -0.00001);
    ck_assert(A[0] - 1.0 < 0.00001);
    ck_assert(A[0] - 1.0 > -0.00001);
}
END_TEST

Suite *utility_suite()
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("utility");
    tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_swap);

    suite_add_tcase(s, tc_core);

    return s;
}