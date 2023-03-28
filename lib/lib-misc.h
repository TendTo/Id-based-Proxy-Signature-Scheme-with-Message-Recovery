/*
 *  Copyright 2016 Mario Di Raimondo <diraimondo@dmi.unict.it>
 *
 *  This source code is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This source code is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LIB_MISC_H
#define LIB_MISC_H

#include <gmp.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>
#include <assert.h>
#include <stdint.h>

#if defined(_WIN32) || defined(__CYGWIN__)
#include <windows.h>
#endif

int extract_randseed_os_rng(uint8_t *seed, size_t seed_bits);
int gmp_randseed_os_rng(gmp_randstate_t state, size_t bits);
unsigned int
non_generic_dlog_secure_size_by_security_level(unsigned int level);
#define generic_dlog_secure_size_by_security_level(level) ((level)*2)

#if defined(PBC_SUPPORT)
#include <pbc/pbc.h>
typedef enum {
    pbc_pairing_type_a,
    pbc_pairing_type_a1,
    pbc_pairing_type_d,
    pbc_pairing_type_e,
    pbc_pairing_type_f,
    pbc_pairing_type_g,
    pbc_pairing_type_i
} pbc_pairing_type_t;

void select_pbc_param_by_security_level(pbc_param_t param,
                                        pbc_pairing_type_t type,
                                        unsigned int level, void *aux);
#endif

#endif /* LIB_MISC_H */
