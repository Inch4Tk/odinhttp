# Odin Http Client
This library provides a lightweight http client written in Odin. The underlying socket is from SDL2.net provided by Odin/Vendor. 


## Installation
```
odin build http -build-mode:dll -out:build/http.dll -show-timings
```

## Example
```
import json "core:encoding/json"
import http "shared:odinhttp/http"

some_proc :: proc () {
    // Error handling just forwarded to "caller procedure"

    // Before you send requests always make a session, keep this session around 
    // for the time you want to make requests.
    // Right now you can (should) only have a single session and it is not threadsafe.
    session := http.make_session() or_return
    defer http.delete_session(session)

    // Example 1
    // Simple get request
    req := http.request_prepare(.Get, "https://xyz.com/404") or_return
    fmt.printf("Request:\n%s\n", req.buffer)

    res := http.request(session, req) or_return
    fmt.printf("Response in %d milliseconds:\n%s\n", res.elapsed_ms, res.buffer)
    
    defer http.request_delete(req)
    defer http.response_delete(res)

    fmt.println("----")

    // Example 2
    // Simple post request
    req2 := http.request_prepare(.Post, "https://xyz.com/404?param=one&param2=two") or_return
    fmt.printf("Request:\n%s\n", req2.buffer)
    
    res2 := http.request(session, req2) or_return
    fmt.printf("Response in %d milliseconds:\n%s\n", res2.elapsed_ms, res2.buffer)

    defer http.request_delete(req2)
    defer http.response_delete(res2)

    fmt.println("----")

    // Example 3
    // Randomly complex post request to show parameters
    headers := make(map[string]string)
    defer delete(headers)
    token := "qwerasdf"
    headers["authorization"] = fmt.tprintf("Bearer %s", token)
    headers["accept-encoding"] = "identity"
    headers["connection"] = "close"
    headers["content-type"] = "application/json"

    cookies := make(map[string]string)
    defer delete(cookies)
    cookies["some_random_cookie] = "with_random_value"
    
    json_body := make(map[string]int)
    defer delete(json_body)
    json_body["key1"] = 0
    json_body["key2"] = 123
    json_body["key3"] = 987
    body_data := json.marshal(json_body)

    req3 := http.request_prepare(.Post, "https://xyz.com/404", 
        headers=headers,
        cookies=cookies,
        body_data=body_data,
        timeout_ms=3000,
    ) or_return
    fmt.printf("Request:\n%s\n", req3.buffer)
    
    res3 := http.request(session, req3) or_return
    fmt.printf("Response in %d milliseconds:\n%s\n", res3.elapsed_ms, res3.buffer)

    defer http.request_delete(req3)
    defer http.response_delete(res3)
}
```

## List of supported behavior
- Http 1.1
- SSL, TLS
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
If you want SSL support you need a valid OpenSSL distribution in your system. For windows it is basically impossible to find trustworthy binaries which include static libraries. 

The recommended version is 3.0.2 (current as of 2022/04/18), which is the version used for developing. Any 3.0.x version should work, no other versions are tested.

This means you have to compile and install them on your own. Follow this official guide: [https://github.com/openssl/openssl#build-and-install](https://github.com/openssl/openssl#build-and-install).

If you want to build without ssl support add the following to your build command:
```-define:SSL_SUPPORT=false```

If you have ssl support disabled all calls with https as schema will unpredictably fail or crash.

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

