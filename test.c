#undef NDEBUG

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <wsock.h>


int main(void) {
  {
    /* unmasked text message "Hello" */
    const uint8_t buf[] = { 0x81, 0x05, 0x48, 0x65, 0x6C, 0x6C, 0x6F, };

    wsock_t wsock = {0};
    const size_t size = wsock_decode(&wsock, buf, sizeof(buf));
    assert(size == 2);

    assert(wsock.fin    == 1);
    assert(wsock.rsv1   == 0);
    assert(wsock.rsv2   == 0);
    assert(wsock.rsv3   == 0);
    assert(wsock.opcode == WSOCK_OPCODE_TEXT);
    assert(wsock.mask   == 0);

    assert(wsock.payload_len == 5);

    assert(strncmp((char*) (buf+size), "Hello", wsock.payload_len) == 0);
  }
  {
    /* masked text message "Hello" */
    uint8_t buf[] = { 0x81, 0x85, 0x37, 0xFA, 0x21, 0x3D, 0x7F, 0x9F, 0x4D, 0x51, 0x58, };

    wsock_t wsock = {0};
    const size_t size = wsock_decode(&wsock, buf, sizeof(buf));
    assert(size == 6);

    assert(wsock.fin    == 1);
    assert(wsock.rsv1   == 0);
    assert(wsock.rsv2   == 0);
    assert(wsock.rsv3   == 0);
    assert(wsock.opcode == WSOCK_OPCODE_TEXT);
    assert(wsock.mask   == 1);

    assert(wsock.payload_len == 5);

    wsock_mask(buf+size, wsock.payload_len, wsock.mask_key);
    assert(strncmp((char*) (buf+size), "Hello", wsock.payload_len) == 0);
  }
  {
    /* 512 bytes binary data */
    const uint8_t buf[] = { 0x82, 0x7E, 0x02, 0x00, };

    wsock_t wsock = {0};
    const size_t size = wsock_decode(&wsock, buf, sizeof(buf));
    assert(size == 4);

    assert(wsock.fin    == 1);
    assert(wsock.rsv1   == 0);
    assert(wsock.rsv2   == 0);
    assert(wsock.rsv3   == 0);
    assert(wsock.opcode == WSOCK_OPCODE_BIN);
    assert(wsock.mask   == 0);

    assert(wsock.payload_len == 512);
  }
  {
    /* 100 GiB binary data */
    const uint8_t buf[] = { 0x82, 0x7F, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x00, };

    wsock_t wsock = {0};
    const size_t size = wsock_decode(&wsock, buf, sizeof(buf));
    assert(size == 10);

    assert(wsock.fin    == 1);
    assert(wsock.rsv1   == 0);
    assert(wsock.rsv2   == 0);
    assert(wsock.rsv3   == 0);
    assert(wsock.opcode == WSOCK_OPCODE_BIN);
    assert(wsock.mask   == 0);

    assert(wsock.payload_len == (uint64_t) 1024*1024*1024*100);
  }
  return EXIT_SUCCESS;
}
