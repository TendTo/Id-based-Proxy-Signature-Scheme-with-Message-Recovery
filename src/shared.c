#include "shared.h"

void swap(void *a, void *b)
{
    void *temp = a;
    a = b;
    b = temp;
}
