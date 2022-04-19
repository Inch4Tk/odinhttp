package http

import "core:c"

SSL_SUPPORT :: #config(SSL_SUPPORT, true)

ODINHTTP_VERSION_MAJOR :: 0
ODINHTTP_VERSION_MINOR :: 1
ODINHTTP_VERSION_PATCH :: 0

HTTP_VERSION :: 11
HTTP_VERSION_STR :: "HTTP/1.1"
HTTP_PORT : u16 : 80
HTTPS_PORT : u16 : 443

// WRITE_MAX_RETRIES :: 1000

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

Http_Error :: enum {
    None,
    Url_Invalid_Scheme,
    Url_Invalid_Ipv6,
    Url_Invalid_Port,
    SDL2Init_Failed,
    Socket_Set_Creation_Error,
    SSL_CTX_New_Failed,
    SSL_Connection_Failed,
    SSL_Loading_Certs_Failed,
    SSL_Verification_Failed,
    Could_Not_Resolve_Host,
    Socket_Creation_Error,
    Socket_Send_Error,
    Socket_Read_Error,
    Buffer_Allocation_Error,
    Response_Header_Invalid,
    Response_Decompression_Failed,
    Response_Chunk_Header_Invalid,
    Unknown_Socket_Error,
    Host_Disconnected,
    Content_Encoding_Not_Supported,
    Timeout,
}


// Socket type definition for sdl type
when ODIN_OS == .Windows && ODIN_ARCH == .amd64 {
    // https://github.com/tpn/winsdk-10/blob/9b69fd26ac0c7d0b83d378dba01080e93349c2ed/Include/10.0.10240.0/um/WinSock2.h#L122
    // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/f959534d-51f2-4103-8fb5-812620efe49b
    SOCKET :: distinct c.uint64_t
} else when ODIN_OS == .Windows {
    SOCKET :: distinct c.uint
} else {
    SOCKET :: distinct c.int
}