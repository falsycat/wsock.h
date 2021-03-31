#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>


typedef struct wsock_t wsock_t;

struct wsock_t {
  uint64_t payload_len;
  uint32_t mask_key;

  unsigned fin  : 1;
  unsigned rsv1 : 1;
  unsigned rsv2 : 1;
  unsigned rsv3 : 1;

  unsigned opcode : 4;
# define WSOCK_OPCODE_CONT  0x0
# define WSOCK_OPCODE_TEXT  0x1
# define WSOCK_OPCODE_BIN   0x2
# define WSOCK_OPCODE_CLOSE 0x8
# define WSOCK_OPCODE_PING  0x9
# define WSOCK_OPCODE_PONG  0xA

  unsigned mask : 1;
};

static inline size_t wsock_encode_size(const wsock_t* wsock) {
  const size_t payload_len =
    wsock->payload_len > UINT16_MAX? 8:
    wsock->payload_len >= 126?       2: 0;
  return 2 + payload_len + (wsock->mask? 4: 0);
}

static inline void wsock_encode(uint8_t* buf, const wsock_t* wsock) {
  *(buf++) =
    (wsock->fin  << 7) |
    (wsock->rsv1 << 6) |
    (wsock->rsv2 << 5) |
    (wsock->rsv3 << 4) | wsock->opcode;

  *buf = wsock->mask << 7;
  if (wsock->payload_len > UINT16_MAX) {
    *(buf++) |= 127;
    *(uint64_t*) buf = wsock->payload_len;
    buf += 8;
  } else if (wsock->payload_len >= 126) {
    *(buf++) |= 126;
    *(uint16_t*) buf = wsock->payload_len;
    buf += 2;
  } else {
    *(buf++) |= wsock->payload_len;
  }

  if (wsock->mask) {
    *(uint32_t*) buf = wsock->mask_key;
    buf += 4;
  }
}

static inline size_t wsock_decode(wsock_t* wsock, const uint8_t* buf, size_t size) {
  const uint8_t* ptr = buf;

  if (size < 2) {
    return 0;
  }
  *wsock = (wsock_t) {
    .fin         = (ptr[0] >> 7) & 0x1,
    .rsv1        = (ptr[0] >> 6) & 0x1,
    .rsv2        = (ptr[0] >> 5) & 0x1,
    .rsv3        = (ptr[0] >> 4) & 0x1,
    .opcode      = ptr[0] & 0xF,
    .mask        = (ptr[1] >> 7) & 0x1,
    .payload_len = ptr[1] & 0x7F,
  };
  size -= 2;
  ptr  += 2;

# define wsock_decode_uint_(name, N) do {  \
    if (size < N/8) {  \
      return 0;  \
    }  \
    wsock->name = *(uint##N##_t*) ptr;  \
    size -= N/8;  \
    ptr  += N/8;  \
  } while (0)

  switch (wsock->payload_len) {
  case 126:
    wsock_decode_uint_(payload_len, 16);
    break;
  case 127:
    wsock_decode_uint_(payload_len, 64);
    break;
  }

  if (wsock->mask) {
    wsock_decode_uint_(mask_key, 32);
  }
  return ptr - buf;

# undef wsock_decode_uint_
}

static inline void wsock_mask(uint8_t* buf, size_t len, uint32_t key) {
  uint32_t*    buf32 = (void*) buf;
  const size_t len32 = len/4;
  for (size_t i = 0; i < len32; ++i) {
    buf32[i] = buf32[i] ^ key;
  }

  buf += len32*4;
  len -= len32*4;

  const uint8_t* key8 = (void*) &key;
  for (size_t i = 0; i < len; ++i) {
    buf[i] = buf[i] ^ key8[i];
  }
}
