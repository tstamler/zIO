/*
 * Copyright 2019 University of Washington, Max Planck Institute for
 * Software Systems, and The University of Texas at Austin
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef MICROBENCH_H_
#define MICROBENCH_H_

#include <stdint.h>
#include <utils.h>

static inline uint64_t rdtsc(void)
{
    uint32_t eax, edx;
    asm volatile ("rdtsc" : "=a" (eax), "=d" (edx));
    return ((uint64_t) edx << 32) | eax;
}

static inline uint32_t kill_cycles(uint32_t cyc, uint32_t opaque)
{
  uint64_t start = rdtsc();
  uint64_t end = start + cyc;

  if (end >= start) {
    while (rdtsc() < end) {
      opaque = opaque * 42 + 37;
      opaque ^= 0x12345678;
      opaque = opaque * 42 + 37;
      opaque ^= 0x87654321;
    }
  } else {
    while (rdtsc() >= start || rdtsc() < end) {
      opaque = opaque * 42 + 37;
      opaque ^= 0x12345678;
      opaque = opaque * 42 + 37;
      opaque ^= 0x87654321;
    }
  }
  return opaque;
}

#endif /* ndef MICROBENCH_H_ */
