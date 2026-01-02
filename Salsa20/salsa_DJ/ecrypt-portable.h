#pragma once
#ifndef ECRYPT_PORTABLE
#define ECRYPT_PORTABLE

#include <stdint.h>

/* Basic typedefs */
typedef uint8_t  u8;
typedef uint32_t u32;

/* Force 32-bit */
#define U32V(v) ((u32)(v))

/* Rotation */
#define ROTL32(v,n) ((U32V(v) << (n)) | (U32V(v) >> (32 - (n))))

/* Load/store little-endian */
#define U8TO32_LITTLE(p) \
  (((u32)((p)[0])) | ((u32)((p)[1]) << 8) | ((u32)((p)[2]) << 16) | ((u32)((p)[3]) << 24))

#define U32TO8_LITTLE(p, v) \
  do { \
    (p)[0] = (u8)((v));       \
    (p)[1] = (u8)((v) >> 8);  \
    (p)[2] = (u8)((v) >> 16); \
    (p)[3] = (u8)((v) >> 24); \
  } while (0)

#endif
