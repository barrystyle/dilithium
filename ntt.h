#ifndef MLDSA65_NTT_H
#define MLDSA65_NTT_H
#include "params.h"
#include <stdint.h>

void MLDSA65_ntt(int32_t a[N]);

void MLDSA65_invntt_tomont(int32_t a[N]);

#endif
