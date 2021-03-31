wsock.h
====

The simplest header-only WebSocket frame decoder/encoder for C11

This library has just three functions:

```C
/* calculates required buffer size to store encoded header  */
size_t wsock_encode_size(const wsock_t* wsock);

/* encodes the header into the buffer, which must be as big as a size returned by wsock_encode_size */
void wsock_encode(uint8_t* buf, const wsock_t* wsock);

/* decodes a header and returns consumed buffer size or 0 when it's incomplete */
size_t wsock_decode(wsock_t* wsock, const uint8_t* buf, size_t size);
```

## Reference

- [RFC 6455, The WebSocket Protocol (日本語訳)](https://triple-underscore.github.io/RFC6455-ja.html)
