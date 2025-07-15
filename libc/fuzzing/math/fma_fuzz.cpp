//===-- fma_fuzz.cpp ------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// Fuzzing test for llvm-libc fma implementation.
///
//===----------------------------------------------------------------------===//

#include "src/math/fma.h"
#include "utils/MPFRWrapper/mpfr_inc.h"
#include <cstdint>
#include <cstring>
#include <iostream>
#include <math.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  mpfr_t in_x;
  mpfr_t in_y;
  mpfr_t in_z;
  mpfr_t out;
  mpfr_init2(in_x, 53);
  mpfr_init2(in_y, 53);
  mpfr_init2(in_z, 53);
  mpfr_init2(out, 53);

  for (size_t i = 0; i < size / (3 * sizeof(double)); ++i) {
    double x;
    double y;
    double z;

    std::memcpy(&x, data, sizeof(double));
    data += sizeof(double);
    std::memcpy(&y, data, sizeof(double));
    data += sizeof(double);
    std::memcpy(&z, data, sizeof(double));
    data += sizeof(double);

    // remove NaN, inf, and signed zeros
    if (isnan(x) || isinf(x) || (signbit(x) && x == 0.0))
      return 0;
    if (isnan(y) || isinf(y) || (signbit(y) && y == 0.0))
      return 0;
    if (isnan(z) || isinf(z) || (signbit(z) && z == 0.0))
      return 0;

    mpfr_set_d(in_x, x, MPFR_RNDN);
    mpfr_set_d(in_y, y, MPFR_RNDN);
    mpfr_set_d(in_z, z, MPFR_RNDN);

    int output = mpfr_fma(out, in_x, in_y, in_z, MPFR_RNDN);
    mpfr_subnormalize(out, output, MPFR_RNDN);
    double to_compare = mpfr_get_d(out, MPFR_RNDN);

    double result = LIBC_NAMESPACE::fma(x, y, z);

    if (result != to_compare) {
      std::cout << std::hexfloat << "Failing x: " << x << std::endl;
      std::cout << std::hexfloat << "Failing y: " << x << std::endl;
      std::cout << std::hexfloat << "Failing z: " << x << std::endl;
      std::cout << std::hexfloat << "Failing output: " << result << std::endl;
      std::cout << std::hexfloat << "Expected: " << to_compare << std::endl;
      __builtin_trap();
    }
  }
  mpfr_clear(in_x);
  mpfr_clear(in_y);
  mpfr_clear(in_z);
  mpfr_clear(out);
  return 0;
}
