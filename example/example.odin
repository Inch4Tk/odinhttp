package http_example

import "core:fmt"
import "core:log"
import json "core:encoding/json"
import http "../http"

log_proc :: proc(data: rawptr, level: log.Level, text: string, options: log.Options, location := #caller_location) {
    fmt.printf("[%s] %s: %s", level, location, text)
}

example_proc :: proc() -> http.Http_Error {
    // Error handling just forwarded to "caller procedure"

    // Enable logging in context to get a bit more outputs on any errors
    context.logger = log.Logger{
        procedure=log_proc,
        data=nil,
        lowest_level=.Debug,
        options=nil,
    }

    // Before you send requests always make a session, keep this session around
    // for the time you want to make requests.
    // Right now you can (should) only have a single session and it is not threadsafe.
    session := http.make_session() or_return
    defer http.delete_session(session)

    // Example 1
    // Simple get request
    req := http.request_prepare(.Get, "http://httpbin.org/get") or_return
    fmt.printf("Request:\n%s\n", req.buffer)

    res := http.request(session, req) or_return
    fmt.printf("Response in %d milliseconds:\n%s\n", res.elapsed_ms, res.buffer)
    fmt.printf("Parsed headers:\n%v\n", res.headers)

    defer http.request_delete(req)
    defer http.response_delete(res)

    fmt.println("----")

    // Example 2
    // Simple post request
    req2 := http.request_prepare(.Post, "https://httpbin.org/post?param=one&param2=two") or_return
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
    cookies["some_random_cookie"] = "with_random_value"

    json_body := make(map[string]int)
    defer delete(json_body)
    json_body["key1"] = 0
    json_body["key2"] = 123
    json_body["key3"] = 987
    body_data := json.marshal(json_body) or_else []u8{}

    req3 := http.request_prepare(
        method=.Post,
        url="https://httpbin.org/post",
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

    return .None
}

main :: proc() {
    err := example_proc()
    if err != nil {
        fmt.printf("Something went wrong %v\n", err)
    }
}