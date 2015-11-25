//
// Do some checks against the libtls headers
//
#include <tls.h>

// AFAIK this value has not changed
#if TLS_API != 20141031
# pragma message("TLS_API version mismatch < " TLS_API)
#endif

// In earlier versions TLS_WANT_POLLIN was TLS_READ_AGAIN
#ifndef TLS_WANT_POLLIN
# error "TLS_WANT_POLLIN is undefined, is this version of libtls too old?"
#endif

#if TLS_WANT_POLLIN != -2
# error "API error TLS_WANT_POLLIN -2 !=", TLS_WANT_POLLIN
#endif

// In earlier versions TLS_WANT_POLLOUT was TLS_WRITE_AGAIN
#ifndef TLS_WANT_POLLOUT
# error "TLS_WANT_POLLOUT is undefined, is this version of libtls too old?"
#endif

#if TLS_WANT_POLLOUT != -3
# error "API error TLS_WANT_POLLOUT -3 !=", TLS_WANT_POLLOUT
#endif

