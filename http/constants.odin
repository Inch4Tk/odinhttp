package http

import "core:c"

SSL_SUPPORT :: #config(SSL_SUPPORT, true)

HTTP_VERSION :: 11
HTTP_VERSION_STR :: "HTTP/1.1"
HTTP_PORT : u16 : 80
HTTPS_PORT : u16 : 443

CS_IDLE :: "Idle"
CS_REQ_STARTED :: "Request-started"
CS_REQ_SENT :: "Request-sent"


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
    Unknown_Socket_Error,
    Host_Disconnected,
    Timeout,
}

when ODIN_OS == .Windows && ODIN_ARCH == .amd64 {
    // https://github.com/tpn/winsdk-10/blob/9b69fd26ac0c7d0b83d378dba01080e93349c2ed/Include/10.0.10240.0/um/WinSock2.h#L122
    // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/f959534d-51f2-4103-8fb5-812620efe49b
    SOCKET :: distinct c.uint64_t
} else when ODIN_OS == .Windows {
    SOCKET :: distinct c.uint
} else {
    SOCKET :: distinct c.int
}