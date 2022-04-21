package http

import "core:time"
import "core:fmt"
import "core:strings"
import "core:strconv"
import "core:slice"
import "core:c"
import "core:log"
import "core:bytes"
import gzip "core:compress/gzip"
import zlib "core:compress/zlib"
import net "vendor:sdl2/net"

Request :: struct {
	// Method and url are just here for informational use.
	// If you want to change them build a new request.
	method:        Http_Method,
	url:           ^Url,
	buffer:        []u8,
	headers_until: u32,
	timeout_ms:    i32,
	keep_alive:    bool,
	use_https:     bool,
}

Response :: struct {
	status_code: u32,
	elapsed_ms:  u32,
	headers:     map[string]string,
	cookies:     map[string]string,
	buffer:      []u8,
	body:        []u8, // this is a slice into the buffer slice
	version:     string,
	reason:      string,
	keep_alive:  bool,
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
	ready:         c.int,
	channel:       SOCKET,
	remoteAddress: net.IPaddress,
	localAddress:  net.IPaddress,
	sFlag:         c.int,
}

// Make and initialize a new session. The session stores keep-alive connections (default in http/1.1)
// and handles sdl2 init and teardown.
make_session :: proc() -> (sess: ^Session, err: Http_Error) {
	// SDL Init
	success := net.Init()
	if success == -1 {
		return nil, .SDL2Init_Failed
	}
	defer if err != .None {
		net.Quit()
	}

	socket_set := net.AllocSocketSet(10)
	if socket_set == nil {
		return nil, .Socket_Set_Creation_Error
	}
	defer if err != .None {
		net.FreeSocketSet(socket_set)
	}

	// OpenSSL Init
	ctx: SSL_CTX
	if SSL_SUPPORT {
		OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nil)

		ctx = SSL_CTX_new(TLS_client_method())
		if ctx == nil {
			return nil, .SSL_CTX_New_Failed
		}

		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nil)
		SSL_CTX_set_verify_depth(ctx, 4)
		SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION)

		if !load_system_certs(ctx) {
			return nil, .SSL_Loading_Certs_Failed
		}
	}

	// Store everything in our session struct
	sess = new(Session)
	sess.connections = make(map[string]Socket)
	sess.socket_set = socket_set
	sess.ssl_ctx = ctx

	return sess, .None
}

// Delete a session
delete_session :: proc(sess: ^Session) {
	net.FreeSocketSet(sess.socket_set)
	for k, socket in sess.connections {
		delete(k)
		net.TCP_Close(socket.socket)
		if socket.ssl != nil {
			SSL_shutdown(socket.ssl)
			SSL_free(socket.ssl)
		}
	}
	delete(sess.connections)
	net.Quit()
	free(sess)
	// openssl will deinit by itself since version 1.1.0 (claimed at least)
}

// Prepare a request before sending it
//
// This function will allocate a new request with the default allocator.
// The user is responsible for freeing the allocated memory of the returned request
// (e.g. using request_delete()).
// Make sure you take care to delete all supplied headers/cookies in the maps you supplied yourself
// deleting the request does not touch those.
//
// Timeout_ms, -1 = wait infinitely, 0 = no wait (not a good idea)
request_prepare :: proc(
	method: Http_Method,
	url: string,
	headers: map[string]string = nil,
	cookies: map[string]string = nil,
	body_data: []u8 = nil,
	timeout_ms: i32 = 60000,
) -> (
	^Request,
	Http_Error,
) {
	assert(timeout_ms >= 0, "Currently only supports positive timeouts, until bug in binding is fixed")
	purl, url_error := url_parse(url)
	if url_error != .None {
		url_free(purl)
		return nil, url_error
	}

	use_https := purl.scheme == "https" ? true : false

	// Build Header
	builder := strings.make_builder(
		0,
		(len(url) + cap(headers) + len(body_data) + cap(cookies)) * 2,
	) // This is just a rough size estimate
	defer strings.destroy_builder(&builder)

	fmt.sbprintf(&builder, "%s %s", method_to_string(method), purl.path != "" ? purl.path : "/")
	if purl.query != "" {
		fmt.sbprintf(&builder, "?%s", purl.query)
	}
	if purl.fragment != "" {
		fmt.sbprintf(&builder, "#%s", purl.fragment)
	}
	fmt.sbprintf(&builder, " %s\r\n", HTTP_VERSION_STR)

	host: string
	if (!use_https && purl.port != HTTP_PORT) || (use_https && purl.port != HTTPS_PORT) {
		host = fmt.tprintf("%s:%d", purl.hostname, purl.port)
	} else {
		host = fmt.tprintf("%s", purl.hostname)
	}
	fmt.sbprintf(&builder, "host: %s\r\n", host)
	fmt.sbprintf(
		&builder,
		"user-agent: odinhttp/%d.%d.%d\r\n",
		ODINHTTP_VERSION_MAJOR,
		ODINHTTP_VERSION_MINOR,
		ODINHTTP_VERSION_PATCH,
	)

	if !("accept" in headers) && !("Accept" in headers) {
		fmt.sbprintf(&builder, "accept: */*\r\n")
	}
	if !("accept-encoding" in headers) && !("Accept-Encoding" in headers) {
		fmt.sbprintf(&builder, "accept-encoding: deflate, gzip\r\n")
	}
	should_keep_alive := false
	if !("connection" in headers) && !("Connection" in headers) {
		fmt.sbprintf(&builder, "connection: keep-alive\r\n")
		should_keep_alive = true
	} else if headers["connection"] == "keep-alive" || headers["Connection"] == "keep-alive" {
		should_keep_alive = true
	}
	for header_key, header_name in headers {
		fmt.sbprintf(&builder, "%s: %s\r\n", header_key, header_name)
	}

	// Add Cookies
	cookie_num := len(slice.map_keys(cookies))
	if cookie_num > 0 {
		fmt.sbprint(&builder, "cookie: ")
		sep := "; "
		cookies_done := 0
		for ck, cv in cookies {
			cookies_done += 1
			if cookies_done == cookie_num {
				sep = ""
			}
			fmt.sbprintf(&builder, "%s=%s%s", ck, cv, sep)
		}
		fmt.sbprint(&builder, "\r\n")
	}
	headers_until := strings.builder_len(builder)

	// Build Body
	fmt.sbprintf(&builder, "content-length: %d\r\n", len(body_data))
	fmt.sbprint(&builder, "\r\n")
	if len(body_data) > 0 {
		strings.write_bytes(&builder, body_data)
	}

	req := new(Request)
	req.method = method
	req.url = purl
	req.buffer = slice.clone(builder.buf[:])
	req.timeout_ms = timeout_ms
	req.keep_alive = should_keep_alive
	req.use_https = use_https
	req.headers_until = u32(headers_until)
	return req, .None
}

// Prints the headers of a request out
request_print_headers :: proc(req: ^Request) {
	fmt.println(req.buffer[:req.headers_until])
}

// Delete a request
request_delete :: proc(req: ^Request) {
	delete(req.buffer)
	url_free(req.url)
	free(req)
}

// Delete a response
response_delete :: proc(res: ^Response) {
	delete(res.buffer)
	delete(res.headers)
	delete(res.cookies)
	free(res)
}

// Send a previously prepared request object
request :: proc(sess: ^Session, req: ^Request) -> (res: ^Response, error: Http_Error) {
	start := time.now()

	succesful_reuse := false
	if socket, ok := sess.connections[req.url.hostname]; ok {
		// Reuse connection
		res, error = handle_protocol(sess, socket, req)
		if error == .None {
			succesful_reuse = true
		} else {
			// Reuse was not successful, host has closed the connection
			// free closed socket then retry by making a new connection (see next if)
			assert(res == nil)
			handle_host_disconnect(sess, socket, req.url.hostname)
			// Except if some other unexpected error happened, directly error out
			if (error != .Host_Disconnected) {return nil, error}
		}
	}

	// Make new connection if we could not reuse the previous connection
	if !succesful_reuse {
		// Deferred failure handler to make cleanup easier
		// If the function returns with something other than .None error, then this will trigger
		socket: net.TCPsocket
		ssl: SSL
		add_socket_success: i32 = -1
		error = .None
		defer if error != .None {
			assert(res == nil)
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
			log.errorf("SDLNet_ResolveHost %s", net.GetError())
			return nil, .Could_Not_Resolve_Host
		}

		socket = net.TCP_Open(&ipaddr)
		if socket == nil {
			log.errorf("SDLNet_TCP_Open %s", net.GetError())
			return nil, .Socket_Creation_Error
		}

		add_socket_success = net.TCP_AddSocket(sess.socket_set, socket)
		if add_socket_success == -1 {
			log.errorf("SDLNet_TCP_AddSocket %s", net.GetError())
			return nil, .Socket_Creation_Error
		}

		// Optional SSL handshake
		if (SSL_SUPPORT && req.use_https) {
			ssl = SSL_new(sess.ssl_ctx)
			if ssl == nil {
				return nil, .SSL_Connection_Failed
			}
			full_socket := transmute(^FullSDLTCPSocket)socket
			// https://stackoverflow.com/questions/1953639/is-it-safe-to-cast-socket-to-int-under-win64
			// so actually not allowed, buuut no choice if we want to use openssl
			// and it seems to be the standard practice anyways
			channel := c.int(full_socket.channel)
			bio := BIO_new_socket(channel, BIO_NOCLOSE)
			if bio == nil {
				return nil, .SSL_Connection_Failed
			}

			SSL_set_bio(ssl, bio, bio)
			// this call should be SSL_set_tlsext_host_name which is a macro,
			// so we can't bind to it. The macro directly resolves to this:
			// https://github.com/openssl/openssl/blob/518ce65d93692ecd4c004b96b47d58da8e5922ea/include/openssl/tls1.h#L259
			sethost_result := SSL_ctrl(
				ssl,
				SSL_CTRL_SET_TLSEXT_HOSTNAME,
				TLSEXT_NAMETYPE_host_name,
				transmute(rawptr)(chost),
			)
			if sethost_result == 0 {
				return nil, .SSL_Connection_Failed
			}

			ssl_handshake_result := SSL_connect(ssl) // cert verification happens here
			if ssl_handshake_result <= 0 {
				err := SSL_get_error(ssl, ssl_handshake_result)
				log.errorf("SSL Error code %i", err)
				return nil, .SSL_Verification_Failed
			}
		}

		// The actual sending/receiving part
		sslsocket := Socket{socket, ssl}
		res = handle_protocol(sess, sslsocket, req) or_return

		// Keep socket open if keep alive is set on both sides
		if req.keep_alive && res.keep_alive {
			sess.connections[strings.clone(req.url.hostname)] = sslsocket
		} else {
			handle_host_disconnect(sess, sslsocket, "")
		}
	}

	assert(res != nil) // if we reach here we expect a valid response
	elapsed_total := u32(time.duration_milliseconds(time.since(start)))
	res.elapsed_ms = elapsed_total
	return res, .None
}

@(private)
handle_host_disconnect :: proc(sess: ^Session, sock: Socket, hostname: string) {
	if sock.ssl != nil {
		SSL_shutdown(sock.ssl)
		SSL_free(sock.ssl)
	}
	net.TCP_DelSocket(sess.socket_set, sock.socket)
	net.TCP_Close(sock.socket)
	if hostname != "" {
		k, v := delete_key(&sess.connections, hostname)
		delete(k)
	}
}

@(private)
handle_protocol :: proc(sess: ^Session, sock: Socket, req: ^Request) -> (
	res: ^Response,
	err: Http_Error,
) {
	// Check if we have anything on our socket
	numready := net.CheckSockets(sess.socket_set, 0)
	if numready == -1 {
		log.errorf("Unknown system level socket error: %s", net.GetError())
		return nil, .Unknown_Socket_Error
	} else if numready > 0 && net.SocketReady(sock.socket) {
		// This can only be a disconnection in http/1.1, since we handle the whole
		// previous protocol flow inside this function, so if the function is called again
		// we want to start another request.
		// Since our target socket is disconnected, we have to create a new socket, so we
		// return back to handle socket creation
		return nil, .Host_Disconnected
	}

	// Send request
	start_time := time.now()
	send(sock, req.buffer) or_return

	for {
		// Loop, but realistically expect to go only once in loop as long as no other
		// socket gets disconnected
		elapsed := i32(time.duration_milliseconds(time.since(start_time)))
		new_timeout := req.timeout_ms > 0 ? max(0, req.timeout_ms - elapsed) : req.timeout_ms
		numready := net.CheckSockets(sess.socket_set, u32(new_timeout))
		if numready == -1 {
			return nil, .Unknown_Socket_Error
		} else if numready > 0 && net.SocketReady(sock.socket) {
			start_time = time.now() // reset the timer for multipart receives

			line_buffer := make([dynamic]u8, 0, 512)
			defer delete(line_buffer)

			res = new(Response)
			growbuffer := bytes.Buffer{}
			defer bytes.buffer_destroy(&growbuffer)
			// Make sure to clean up if we get some error
			defer if err != .None {
				log.errorf("Failed parsing response at following line: '%s'", line_buffer)
				response_delete(res)
				res = nil
			}

			// Parse headers
			// Response line
			read_line(sock, &line_buffer) or_return
			parse_response_line(res, line_buffer[:]) or_return

			// Store response line, read first header line
			bytes.buffer_write(&growbuffer, line_buffer[:])
			read_line(sock, &line_buffer) or_return
			for !(len(line_buffer) == 2 && string(line_buffer[:]) == "\r\n") {
				// Loop reads until it hits an empty line (=\r\n), which is the line before
				// the body starts
				hkey, hval := parse_header_line(res, line_buffer[:]) or_return

				// Store last line, read next header line
				bytes.buffer_write(&growbuffer, line_buffer[:])
				read_line(sock, &line_buffer) or_return
			}
			if hval := res.headers["connection"]; hval == "close" {
				res.keep_alive = false
			}
			if req.method == .Head {
				res.buffer = slice.clone(growbuffer.buf[:])
				res.body = nil
				return res, .None
			}

			// Parse body
			body_start := bytes.buffer_length(&growbuffer)
			clength := res.headers["content-length"]
			body_length_compressed := strconv.parse_int(clength) or_else 0
			chunked := strings.contains(res.headers["transfer-encoding"], "chunked")
			compressed_buffer: []u8
			defer delete(compressed_buffer)
			if chunked {
				// Hard case: Chunked transport encoding, load data in chunks and merge them
				all_chunks := bytes.Buffer{}
				chunk_buffer: []u8
				defer bytes.buffer_destroy(&all_chunks)
				defer delete(chunk_buffer)
				for {
					read_line(sock, &line_buffer) or_return
					chunk_bytes := parse_chunk_line(line_buffer[:]) or_return
					chunk_length := int(chunk_bytes) + 2
					if chunk_buffer == nil {
						// Make sure we are not allocating the buffer all the time again
						chunk_buffer = make([]u8, max(chunk_length, 1024))
					} else if len(chunk_buffer) < chunk_length {
						delete(chunk_buffer)
						chunk_buffer = make([]u8, chunk_length)
					}
					read_bytes(sock, raw_data(chunk_buffer), i32(chunk_length))
					if chunk_bytes == 0 {
						// Last chunk
						break
					}
					// Discard the crlf sequence at the end of the chunk
					bytes.buffer_write(&all_chunks, chunk_buffer[:chunk_bytes])
				}
				// now write back full contents of all chunks to compressed buffer
				compressed_buffer = slice.clone(bytes.buffer_to_bytes(&all_chunks))
				body_length_compressed = len(compressed_buffer)
			} else if body_length_compressed > 0 {
				// Easy case: We get body length, just load everything into one buffer
				compressed_buffer = make([]u8, body_length_compressed)
				read_bytes(sock, raw_data(compressed_buffer), i32(body_length_compressed)) or_return
			}

			// Decompress body
			compression := res.headers["content-encoding"]
			if compression == "" {
				// No compression, so "compressed_buffer" actually contains uncompressed
				bytes.buffer_write(&growbuffer, compressed_buffer)
			} else {
				decompressed := bytes.Buffer{}
				defer bytes.buffer_destroy(&decompressed)
				switch compression {
				case "gzip":
					err := gzip.load(
						slice = compressed_buffer,
						buf = &decompressed,
						known_gzip_size = len(compressed_buffer),
					)
					if err != nil {
						return nil, .Response_Decompression_Failed
					}
				case "deflate":
					err := zlib.inflate(input = compressed_buffer, buf = &decompressed)
					if err != nil {
						return nil, .Response_Decompression_Failed
					}
				case "br":
					return nil, .Content_Encoding_Not_Supported
				case "compress":
					return nil, .Content_Encoding_Not_Supported

				}
				bytes.buffer_write(&growbuffer, bytes.buffer_to_bytes(&decompressed))
			}

			// Store everything in res
			res.buffer = slice.clone(bytes.buffer_to_bytes(&growbuffer))
			res.body = body_length_compressed > 0 ? res.buffer[body_start:] : nil
			return res, .None
		} else if numready > 0 {
			// Another socket got ready, which means it got disconnected. Remove that socket.
			// We do not have to return here, since it was not our target socket that got
			// disconnected -> we can still wait for target socket replies.
			// Since multiple sockets could conceivably get disconnected we have to loop.
			// We expect only one loop here.
			to_delete := make([dynamic]string)
			defer delete(to_delete)
			for k, s in sess.connections {
				if s.socket != sock.socket && net.SocketReady(s.socket) {
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

@(private)
send :: proc(sock: Socket, data: []u8) -> Http_Error {
	if SSL_SUPPORT && sock.ssl != nil {
		ret := SSL_write(sock.ssl, slice.as_ptr(data), c.int(len(data)))
		if ret <= 0 {
			err := SSL_get_error(sock.ssl, ret)
			return .Socket_Send_Error
			// retries := WRITE_MAX_RETRIES
			// for ; retries >= 0 && err == SSL_ERROR_WANT_WRITE; retries -= 1 {
			//     // TODO: Determine if we can write to socket at all
			//     // Otherwise this will always produce at least 1 sec lag if it failed
			//     // and a thousand retries...
			//     time.sleep(time.Millisecond)
			//     ret = SSL_write(ssl, slice.as_ptr(data), c.int(len(data)))
			//     if ret > 0 {
			//         return .None
			//     }
			//     err = SSL_get_error(ssl, ret)
			// }
			// if ret <= 0 {
			//     return .Socket_Write_Failed
			// }
		}
		return .None
	} else {
		length := c.int(len(data))
		sent_length := net.TCP_Send(sock.socket, slice.as_ptr(data), length)
		if sent_length < length {
			log.errorf("SDLNet_TCP_Send %s", net.GetError())
			return .Socket_Send_Error
		}
		return .None
	}
}

@(private)
read_line :: proc(sock: Socket, buffer: ^[dynamic]u8) -> Http_Error {
	clear(buffer)
	b: u8
	for b != '\n' {
		read_byte(sock, &b) or_return
		append(buffer, b)
	}
	return .None
}

@(private)
read_byte :: proc(sock: Socket, b: ^u8) -> Http_Error {
	if SSL_SUPPORT && sock.ssl != nil {
		SSL_read(sock.ssl, b, 1)
		return .None
	} else {
		net.TCP_Recv(sock.socket, b, 1)
		return .None
	}
	return .Socket_Read_Error
}

@(private)
read_bytes :: proc(sock: Socket, b: rawptr, len: i32) -> Http_Error {
	if SSL_SUPPORT && sock.ssl != nil {
		SSL_read(sock.ssl, b, len)
		return .None
	} else {
		net.TCP_Recv(sock.socket, b, len)
		return .None
	}
	return .Socket_Read_Error
}

@(private)
check_line_ending :: proc(line: []u8) -> Http_Error {
	if len(line) < 2 {
		return .Response_Header_Invalid
	}
	line_end := string(line[len(line) - 2:])
	if line_end != "\r\n" {
		return .Response_Header_Invalid
	}
	return .None
}

@(private)
parse_response_line :: proc(res: ^Response, line: []u8) -> Http_Error {
	check_line_ending(line) or_return

	mode, v_start, v_end, sc_start, sc_end, r_start, r_end: int
	for char, i in line {
		if char == '/' && mode == 0 {
			v_start = i + 1
			mode += 1
		} else if char == ' ' && mode == 1 {
			v_end = i
			sc_start = i + 1
			mode += 1
		} else if char == ' ' && mode == 2 {
			sc_end = i
			r_start = i + 1
			mode += 1
		} else if char == '\r' && mode == 3 {
			r_end = i
			break
		}
	}

	if v_start == 0 || v_end == 0 || sc_start == 0 || sc_end == 0 || r_start == 0 || r_end == 0 {
		return .Response_Header_Invalid
	}

	res.version = strings.clone(string(line[v_start:v_end]))
	res.status_code = u32(strconv.parse_uint(string(line[sc_start:sc_end])) or_else 0)
	res.reason = strings.clone(string(line[r_start:r_end]))

	if (res.status_code == 0) {
		return .Response_Header_Invalid
	}

	return .None
}

@(private)
parse_header_line :: proc(res: ^Response, line: []u8) -> (
	key: string,
	value: string,
	err: Http_Error,
) {
	check_line_ending(line) or_return

	splits := strings.split_n(string(line), ":", 2, context.temp_allocator)
	if len(splits) != 2 {
		err = .Response_Header_Invalid
		return
	}
	key = strings.to_lower(splits[0]) // always allocates
	value = strings.trim_space(splits[1]) // never allocates
	if key == "set-cookie" {
		delete(key)
		cookie := strings.split_n(value, "=", 2, context.temp_allocator)
		if len(cookie) != 2 {
			err = .Response_Header_Invalid
			return
		}
		vtmp := value
		key = strings.clone(cookie[0])
		value = strings.clone(cookie[1])
		res.cookies[key] = value
		delete(vtmp)
	} else {
		res.headers[key] = strings.clone(value)
	}
	err = .None
	return
}

@(private)
parse_chunk_line :: proc(line: []u8) -> (bytes: i32, err: Http_Error) {
	check_line_ending(line) or_return
	no_terminator_line := line[:len(line) - 2]

	splits := strings.split(string(no_terminator_line), ";", context.temp_allocator)
	bytes = i32(strconv.parse_int(splits[0], 16) or_else -1)
	if bytes == -1 {
		return bytes, .Response_Chunk_Header_Invalid
	}
	if len(splits) > 1 {
		// TODO: to support chunk extensions, take splits[1:], then add a return field for them
	}
	return bytes, .None
}
