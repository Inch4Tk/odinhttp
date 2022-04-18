package http

import "core:time"
import "core:fmt"
import "core:strings"
import "core:slice"
import "core:c"
import "core:log"
import net "vendor:sdl2/net"

HTTP_METHODS := [7]string{"GET", "OPTIONS", "HEAD", "POST", "PUT", "PATCH", "DELETE"}

Http_Method :: enum {
    Get,
    Options,
    Head,
    Post,
    Put,
    Patch,
    Delete,
}

method_to_string :: proc(method: Http_Method) -> string {
    return HTTP_METHODS[int(method)]
}

string_to_method :: proc(method: string) -> Http_Method {
    switch method {
    case "GET":
        return .Get
    case "OPTIONS":
        return .Options
    case "HEAD":
        return .Head
    case "POST":
        return .Post
    case "PUT":
        return .Put
    case "PATCH":
        return .Patch
    case "DELETE":
        return .Delete
    case:
        return .Get
    }
}

Request :: struct {
    url:        ^Url,
    buffer:     []u8,
    timeout_ms: i32,
    keep_alive: bool,
    use_https: bool,
}

Response :: struct {
    // cookies
    elapsed_ms: u32,
}

Socket :: struct {
    socket: net.TCPsocket,
    ssl:    SSL,
}

Session :: struct {
    connections: map[string]Socket,
    socket_set:  net.SocketSet,
    ssl_ctx:     SSL_CTX,
}

@(private)
FullSDLTCPSocket :: struct {
    // Expose full sdl sockets, since we need to get the internal socket for ssl
    // https://github.com/SDL-mirror/SDL_net/blob/master/SDLnetTCP.c
    ready: c.int,
    channel: SOCKET,
    remoteAddress: net.IPaddress,
    localAddress: net.IPaddress,
    sFlag: c.int,
}

// Make and initialize a new session. The session stores keep-alive connections (default in http/1.1)
// and handles sdl2 init and teardown.
make_session :: proc() -> (^Session, Http_Error) {
    // SDL Init
    success := net.Init()
    if success == -1 {
        return nil, .SDL2Init_Failed
    }

    socket_set := net.AllocSocketSet(10)
    if socket_set == nil {
        return nil, .Socket_Set_Creation_Error
    }

    // OpenSSL Init
    ctx : SSL_CTX
    if SSL_SUPPORT {
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nil)
        OPENSSL_config(nil)

        ctx = SSL_CTX_new(TLS_client_method())
        if ctx == nil {
            return nil, .SSL_CTX_New_Failed
        }

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nil)
        SSL_CTX_set_verify_depth(ctx, 4)
        SSL_CTX_set_options(ctx,
            SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION,
        )
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)

        if !load_system_certs(ctx) {
            return nil, .SSL_Loading_Certs_Failed
        }
    }

    // Store everything in our session struct
    sess := new(Session)
    sess.connections = make(map[string]Socket)
    sess.socket_set = socket_set
    sess.ssl_ctx = ctx

    return sess, .None
}

// Delete a session
delete_session :: proc(sess: ^Session) {
    net.FreeSocketSet(sess.socket_set)
    for _, socket in sess.connections {
        net.TCP_Close(socket.socket)
        if socket.ssl != nil {
            SSL_shutdown(socket.ssl)
            SSL_free(socket.ssl)
        }
    }
    net.Quit()
    delete(sess.connections)
    free(sess)
    // openssl will deinit by itself since version 1.1.0
}

// Prepare a request before sending it
//
// This function will allocate a new request with the default allocator.
// The user is responsible for freeing the allocated memory of the returned request
// (e.g. using request_delete()).
//
// Timeout_ms, -1 = wait infinitely, 0 = no wait (not a good idea)
request_prepare :: proc(
    method: Http_Method,
    url_target: string,
    headers: map[string]string = nil,
    params: map[string]string = nil,
    string_data: string = "",
    binary_data: []u8 = nil,
    cookies: map[string]string = nil,
    timeout_ms: i32 = 60000,
) -> (
    ^Request,
    Http_Error,
) {
    assert(
        timeout_ms >= 0,
        "Currently only supports positive timeouts, until bug in binding is fixed",
    )
    url, url_error := url_parse(url_target)
    if url_error != nil {
        url_free(url)
        return nil, url_error
    }

    // Build Header
    builder := strings.make_builder(
        0,
        (len(url_target) +
        cap(headers) +
        cap(params) +
        len(string_data) +
        len(binary_data) +
        cap(cookies)) *
        2,
    ) // This is just a rough size estimate
    defer strings.destroy_builder(&builder)

    fmt.sbprintf(
        &builder,
        "%s %s?%s#%s %s\r\n",
        method_to_string(method),
        url.path,
        url.query,
        url.fragment,
        HTTP_VERSION_STR,
    )
    fmt.sbprintf(&builder, "Host: %s\r\n", url.hostname)
    fmt.sbprintf(&builder, "User-Agent: odinhttp/0.1.0\r\n")

    if !("Accept" in headers) {
        fmt.sbprintf(&builder, "Accept: */*\r\n")
    }
    if !("Accept-Encoding" in headers) {
        fmt.sbprintf(&builder, "Accept-Encoding: deflate, gzip\r\n")
    }
    should_keep_alive := false
    if !("Connection" in headers) {
        fmt.sbprintf(&builder, "Connection: keep-alive\r\n")
        should_keep_alive = true
    } else if headers["Connection"] == "keep-alive" {
        should_keep_alive = true
    }
    for header_key, header_name in headers {
        fmt.sbprintf(&builder, "%s: %s\r\n", header_key, header_name)
    }

    // Build Body


    log.info(strings.to_string(builder))
    req := new(Request)
    req.url = url
    req.buffer = slice.clone(builder.buf[:])
    req.timeout_ms = timeout_ms
    req.keep_alive = should_keep_alive
    req.use_https = url.scheme == "https" ? true : false

    return req, .None
}

// Delete a request
request_delete :: proc(req: Request) {
    delete(req.buffer)
    url_free(req.url)
}

// Send a previously prepared request object
request :: proc(sess: ^Session, req: ^Request) -> (res: ^Response, error: Http_Error) {
    start := time.now()

    binary_res: u8
    succesful_reuse := false
    if socket, ok := sess.connections[req.url.hostname]; ok {
        // Reuse connection
        binary_res, err := handle_protocol(sess, socket, req)
        if err == nil {
            succesful_reuse = true
        } else if err == .Host_Disconnected {
            // Reuse was not successful, host has closed the connection
            handle_host_disconnect(sess, socket, req.url.hostname)
        } else {
            // Some other unexpected error happened, report to user
            return nil, .Unknown_Socket_Error
        }
    }


    // Make new connection if we could not reuse the previous connection
    if !succesful_reuse {
        // Defered failure handler to make cleanup easier
        socket : net.TCPsocket
        ssl : SSL
        add_socket_success : i32 = -1
        failed_somewhere := false
        defer if failed_somewhere {
            if ssl != nil {
                SSL_shutdown(ssl)
                SSL_free(ssl)
            }
            if add_socket_success != -1 && socket != nil {
                net.TCP_DelSocket(sess.socket_set, socket)
            }
            if socket != nil {
                net.TCP_Close(socket)
            }
        }

        // Socket creation etc
        ipaddr := net.IPaddress{}
        chost := strings.clone_to_cstring(req.url.hostname)
        defer delete(chost)
        resolve_success := net.ResolveHost(&ipaddr, chost, req.url.port)
        if resolve_success == -1 {
            failed_somewhere = true
            return nil, .Could_Not_Resolve_Host
        }

        socket = net.TCP_Open(&ipaddr)
        if socket != nil {
            failed_somewhere = true
            return nil, .Socket_Creation_Error
        }

        add_socket_success = net.TCP_AddSocket(sess.socket_set, socket)
        if add_socket_success == -1 {
            failed_somewhere = true
            return nil, .Socket_Creation_Error
        }

        // Optional SSL handshake
        if (SSL_SUPPORT && req.use_https) {
            failed_somewhere = true
            ssl = SSL_new(sess.ssl_ctx)
            if ssl == nil {
                failed_somewhere = true
                return nil, .SSL_Connection_Failed
            }
            full_socket := transmute(^FullSDLTCPSocket)socket
            // https://stackoverflow.com/questions/1953639/is-it-safe-to-cast-socket-to-int-under-win64
            // so actually not allowed, buuut no choice if we want to use openssl
            // and it seems to be the standard practice anyways
            channel := c.int(full_socket.channel)
            bio := BIO_new_socket(channel, BIO_NOCLOSE)
            if bio == nil {
                failed_somewhere = true
                return nil, .SSL_Connection_Failed
            }

            SSL_set_bio(ssl, bio, bio)
            sethost_result := SSL_set_tlsext_host_name(ssl, chost)
            if sethost_result == 0 {
                failed_somewhere = true
                return nil, .SSL_Connection_Failed
            }

            ssl_handshake_result := SSL_connect(ssl) // cert verification happens here
            if ssl_handshake_result <= 0 {
                failed_somewhere = true
                err := SSL_get_error(ssl, ssl_handshake_result)
                log.errorf("SSL Error code %i", err)
                return nil, .SSL_Verification_Failed
            }
        }

        // The actual sending part
        sslsocket := Socket{socket, ssl}
        binary_res := handle_protocol(sess, sslsocket, req) or_return

        if req.keep_alive {
            sess.connections[req.url.hostname] = sslsocket
        } else {
            handle_host_disconnect(sess, sslsocket, "")
        }
    }

    elapsed_total := u32(time.duration_milliseconds(time.since(start)))
    res = new(Response)
    res.elapsed_ms = elapsed_total
    return res, .None
}

@(private)
handle_host_disconnect :: proc(sess: ^Session, socket: Socket, hostname: string) {
    using socket
    if ssl != nil {
        SSL_shutdown(ssl)
        SSL_free(ssl)
    }
    net.TCP_DelSocket(sess.socket_set, socket)
    net.TCP_Close(socket)
    if hostname != "" {
        delete_key(&sess.connections, hostname)
    }
}

@(private)
handle_protocol :: proc(sess: ^Session, socket: Socket, req: ^Request) -> (
    []u8,
    Http_Error,
) {
    using socket
    // Check if we have anything on our socket
    numready := net.CheckSockets(sess.socket_set, 0)
    if numready == -1 {
        log.errorf("Unknown system level socket error: %s", net.GetError())
        return nil, .Unknown_Socket_Error
    } else if numready > 0 && net.SocketReady(socket) {
        // This can only be a disconnection in http/1.1, since we handle the whole
        // previous protocol flow inside this function, so if the function is called again
        // we want to start another request.
        // Since our target socket is disconnected, we have to create a new socket, so we
        // return back to handle socket creation
        return nil, .Host_Disconnected
    }

    // Send request
    start_time := time.now()
    result := net.TCP_Send(socket, slice.as_ptr(req.buffer), i32(len(req.buffer)))
    if result < i32(len(req.buffer)) {
        log.errorf("SDLNet_TCP_Send %s", net.GetError())
        return nil, .Socket_Send_Error
    }

    for {
        elapsed := i32(time.duration_milliseconds(time.since(start_time)))
        new_timeout := req.timeout_ms > 0 ? max(0, req.timeout_ms - elapsed) : req.timeout_ms
        // Loop, but realistically expect to go only once in loop as long as no other
        // socket gets disconnected
        numready := net.CheckSockets(sess.socket_set, u32(new_timeout))
        if numready == -1 {
            return nil, .Unknown_Socket_Error
        } else if numready > 0 && net.SocketReady(socket) {
            start_time = time.now() // reset the timer for multipart receives
            net.GetError()
            // TODO: read
            return nil, .None
        } else if numready > 0 {
            // Another socket got ready, which means it got disconnected. Remove that socket.
            // We do not have to return here, since it was not our target socket that got
            // disconnected -> we can still wait for target socket replies.
            // Since multiple sockets could conceivably get disconnected we have to loop.
            // We expect only one loop here.
            to_delete := make([dynamic]string)
            defer delete(to_delete)
            for k, s in sess.connections {
                if net.SocketReady(s.socket) {
                    append(&to_delete, k)
                }
            }
            for k in to_delete {
                handle_host_disconnect(sess, sess.connections[k], k)
            }
        } else if i32(time.duration_milliseconds(time.since(start_time))) > req.timeout_ms {
            // Abort request because of timeout
            return nil, .Timeout
        }
    }
}
