# Odin Http Client
This library provides a lightweight http client written in Odin. The underlying socket is from SDL2.net provided by Odin/Vendor. 


## Installation
**Windows Note:** Before running your program make sure the following dlls are somewhere on the environment path or in the working directory:
- SDL2.dll (from odin/vendor/sdl2)
- SDL2_net.dll (from odin/vendor/sdl2/net)
- If you want to send https requests, see SSL Support section

```
// inside odin/shared
// git clone -b <tagname> <repository>
// then in project:
import http "shared:odinhttp/http"

// alternatively to run tests, inside odinhttp folder:
// for some reason the builtin test does not work (?)
odin run test
```

## Example
For a more complete example check example/example.odin
```
// Before you send requests always make a session, keep this session around
// for the time you want to make requests.
// Right now you can (should) only have a single session and it is not threadsafe.
session := http.make_session() or_return
defer http.delete_session(session)

// Example: Simple get request
req := http.request_prepare(.Get, "https://xyz.com/404") or_return
fmt.printf("Request:\n%s\n", req.buffer)

res := http.request(session, req) or_return
fmt.printf("Response in %d milliseconds:\n%s\n", res.elapsed_ms, res.buffer)

defer http.request_delete(req)
defer http.response_delete(res)
```

## List of supported behavior
- Http 1.1
- SSL/TLS (compile with SSL Support see below)
- All methods (except CONNECT)
- Headers
- Params
- Body as binary/bytestring data
- Cookies (as Odin map)
- content-encoding: deflate and gzip (automatically set to accept both)
- Timeout

## List of unsupported behavior
This is an **incomplete** list of unsupported behavior
- Http2
- Redirects
- "Expect: 100 Continue" requests/responses 
- Http tunnels (Method = CONNECT)
- Proxies
- CookieJar (only supports cookies that are supplied as Odin map)
- Ipv6 (no SDL2.net support)
- Parallel requests (library is not threadsafe)
- Charset is assumed to always be utf8
- transfer-encoding: compress, gzip, deflate (this is unlikely to be used when content-encoding is set, which is the preferred way to do compression anyways)
- Chunked requests (only responses can be chunked)
- Chunk extensions
- Timeouts will not work reliably when servers misbehave and send incomplete messages while keeping the connection open
    - If a server does not send crlf as last line of header
    - If any chunk was not sent completely. This is partly a limitation in SDL, since there is no timeout on read.
    - Probably others
- No support for brotli encoding (if someone makes bindings for brotli, I will happily add this)

## Authorization
Add the authorization headers of your choice yourself. Examples:
```
// Bearer:
token := "...."
headers := make(map[string]string)
defer delete(headers)
headers["authorization"] = fmt.tprintf("Bearer %s", token)
req, err := request_prepare(.Get, "https://xyz.com/404", headers=headers)

// Basic
// expects username/password in base64 encoding separated with ":"
import "core:mem"
import base64 "core:encoding/base64"
username := "...."
password := "...."
headers := make(map[string]string)
defer delete(headers)
concat := fmt.tprintf("%s:%s", username, password)
// have to do some acrobatics to get []u8 from string without copy, is there a better way?
bytecrobatics : []u8 = mem.slice_ptr(strings.ptr_from_string(concat), len(concat))
headers["authorization"] = fmt.tprintf("Basic %s", base64.encode(bytecrobatics))
req, err := request_prepare(.Get, "https://xyz.com/404", headers=headers)
```

## Content-Types
Before sending a request, convert any content-types and input them as byte array. The same goes for content-types received. The response will only contain a byte buffer of the body. Conversion of the content-type has to happen in the calling code.

```
// Form data
headers := make(map[string]string)
defer delete(headers)
headers["content-type"] = "application/x-www-form-urlencoded"
body_data := "parameter1=value&anykeyname=anothervalue"
req, err := request_prepare(.Post, "https://xyz.com/404", headers=headers, body_data=body_data)
```

For building bodies with other complex types refer to here:
- [https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types]

Content-Length header will be set automatically based on the body size

## SSL Support 
If you want SSL support you need a valid OpenSSL distribution in your system. 
The recommended version is 3.0.2 (latest as of 2022/04/18), which is the version used for developing. Any 3.0.x version should work, no other versions are tested.

If you want to build with ssl support add the following to your build command:
```-define:SSL_SUPPORT=true```
If you have ssl support disabled all calls with "https" as schema will unpredictably fail or crash.


### ... and Windows
For windows it is basically impossible to find trustworthy binaries which include static libraries. For exactly the same reason I decided to not upload my own build of them into git.

This means you have to compile and install them on your own. Follow this official guide: [https://github.com/openssl/openssl#build-and-install](https://github.com/openssl/openssl#build-and-install).

Then copy libcrypto.lib and libssl.lib into the lib folder of the http project.

Furthermore make sure that the following files are on the environment path or inside your project folder:
- libssl-3-x64.dll (from openssl/bin)
- libcrypto-3-x64.dll (from openssl/bin)

### ... and Unix
Not tested, but it should work out of the box if you have openssl installed. Most likely you will need to have version 3.0.x, which you will probably have to manually install since the latest official binaries on most distros should be version 1.1.1.

Open an issue if the paths inside ssl.odin are not correct.

### SSL and timeouts
If you set the timeout in your request, this will have no effect on ssl handshake timeouts. The default OpenSSL timeout is set to 300 seconds. If you want to modify this value, call `SSL_CTX_set_timeout(ctx, long)` on the ssl_ctx after calling make_session.

## Warning/Disclaimer
No guarantees are made regarding spec adherence and feature support. I only supported what was needed to make http requests for my purposes and what was easy to implement. Multiple features are not covered by any automatic testing. Also, many parameters are not checked for correct ranges, make sure you check what you send if you want to be sure. 

The library is not guaranteed to be bugfree. **Do not use it to send any sensitive information**.

## Acknowledgements
I took a lot of good ideas and knowledge on implementation from this cpp http library (https://github.com/yhirose/cpp-httplib). Especially in regards to OpenSSL.

Some ideas on the general url and http request formats also came from the python sourcecode and the python requests package.

## Further support
I do not plan to add any more features, as long as my personal requirements do not change. But I would be very happy to accept PRs regarding issues and improvements.

