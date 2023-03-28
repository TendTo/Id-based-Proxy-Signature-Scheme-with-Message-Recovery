#include "sv-scheme.h"

void setup(sv_shared_params_t shared_p, sv_private_params_t private_p, int lambda)
{
    pbc_param_t pairing_p;
    select_pbc_param_by_security_level(pairing_p, pbc_pairing_type_a, lambda, NULL);
    pairing_init_pbc_param(shared_p->pairing, pairing_p);
    pbc_param_clear(pairing_p);

    // Private params init
    element_init_Zr(private_p->sk, shared_p->pairing);

    // Private params setup
    element_random(private_p->sk);

    // Shared params init
    element_init_G1(shared_p->P, shared_p->pairing);
    element_init_G1(shared_p->pk, shared_p->pairing);

    // Shared params setup
    element_random(shared_p->P);
    element_mul_zn(shared_p->pk, shared_p->P, private_p->sk);
}

void shared_param_clear(sv_shared_params_t shared_p)
{
    element_clear(shared_p->P);
    element_clear(shared_p->pk);
    pairing_clear(shared_p->pairing);
}

void private_param_clear(sv_private_params_t private_p)
{
    element_clear(private_p->sk);
}