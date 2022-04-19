package http

import "core:c"

// ###############################################################################
// OpenSSL BINDINGS
// ###############################################################################

when ODIN_OS == .Windows && SSL_SUPPORT {
	foreign import libcrypto "../lib/libcrypto.lib"
	foreign import libssl "../lib/libssl.lib"
} else when SSL_SUPPORT {
	foreign import libcrypto "system:libcrypto"
	foreign import libssl "system:libssl"
}

SSL_METHOD :: distinct rawptr
SSL_CTX :: distinct rawptr
SSL_BIO :: distinct rawptr
SSL :: distinct rawptr
X509_STORE_CTX :: distinct rawptr
X509_STORE :: distinct rawptr
X509 :: distinct rawptr

OPENSSL_INIT_SETTINGS :: distinct rawptr

// Defines
OPENSSL_INIT_NO_LOAD_SSL_STRINGS: c.uint64_t : 0x00100000
OPENSSL_INIT_LOAD_SSL_STRINGS: c.uint64_t : 0x00200000
OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS: c.uint64_t : 0x00000001
OPENSSL_INIT_LOAD_CRYPTO_STRINGS: c.uint64_t : 0x00000002

SSL_VERIFY_NONE: c.int : 0x00
SSL_VERIFY_PEER: c.int : 0x01
SSL_VERIFY_FAIL_IF_NO_PEER_CERT: c.int : 0x02
SSL_VERIFY_CLIENT_ONCE: c.int : 0x04
SSL_VERIFY_POST_HANDSHAKE: c.int : 0x08

SSL_OP_NO_COMPRESSION :: (c.uint64_t(1) << 16)
SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION :: (c.uint64_t(1) << 17)

SSL_ERROR_NONE :: 0
SSL_ERROR_SSL :: 1
SSL_ERROR_WANT_READ :: 2
SSL_ERROR_WANT_WRITE :: 3
SSL_ERROR_WANT_X509_LOOKUP :: 4
SSL_ERROR_SYSCALL :: 5
SSL_ERROR_ZERO_RETURN :: 6
SSL_ERROR_WANT_CONNECT :: 7
SSL_ERROR_WANT_ACCEPT :: 8
SSL_ERROR_WANT_ASYNC :: 9
SSL_ERROR_WANT_ASYNC_JOB :: 10
SSL_ERROR_WANT_CLIENT_HELLO_CB :: 11
SSL_ERROR_WANT_RETRY_VERIFY :: 12

BIO_NOCLOSE: c.int : 0x00
BIO_CLOSE: c.int : 0x01

// Callbacks
SSL_verify_cb :: proc(preverify_ok: c.int, x509_ctx: X509_STORE_CTX) -> c.int

when SSL_SUPPORT {
	@(default_calling_convention = "c")
	foreign libcrypto {
		d2i_X509 :: proc(a: ^X509, ppin: ^^c.uchar, length: c.long) -> X509 ---
		X509_STORE_add_cert :: proc(ctx: X509_STORE, x: X509) -> c.int ---
		X509_free :: proc(x: X509) ---
	}

	@(default_calling_convention = "c")
	foreign libssl {
		// Functions
		OPENSSL_version_major :: proc() -> c.uint ---
		OPENSSL_version_minor :: proc() -> c.uint ---
		OPENSSL_version_patch :: proc() -> c.uint ---

		OPENSSL_init_ssl :: proc(opts: c.uint64_t, settings: OPENSSL_INIT_SETTINGS) -> c.int ---

		TLS_client_method :: proc() -> SSL_METHOD ---

		SSL_CTX_new :: proc(method: SSL_METHOD) -> SSL_CTX ---
		SSL_CTX_free :: proc(ctx: SSL_CTX) ---
		SSL_CTX_set_verify :: proc(ctx: SSL_CTX, mode: c.int, verify_callback: SSL_verify_cb) ---
		SSL_CTX_set_verify_depth :: proc(ctx: SSL_CTX, depth: c.int) ---
		SSL_CTX_set_default_verify_paths :: proc(ctx: SSL_CTX) -> c.int ---
		SSL_CTX_get_timeout :: proc(ctx: SSL_CTX) -> c.long ---
		SSL_CTX_set_timeout :: proc(ctx: SSL_CTX, t: c.long) -> c.long ---
		SSL_CTX_get_options :: proc(ctx: SSL_CTX) -> c.uint64_t ---
		SSL_CTX_set_options :: proc(ctx: SSL_CTX, options: c.uint64_t) -> c.uint64_t ---
		SSL_CTX_get_cert_store :: proc(ctx: SSL_CTX) -> X509_STORE ---

		BIO_new_socket :: proc(sock: c.int, close_flag: c.int) -> SSL_BIO ---

		SSL_new :: proc(ctx: SSL_CTX) -> SSL ---
		SSL_free :: proc(ssl: SSL) ---
		SSL_set_bio :: proc(ssl: SSL, rbio: SSL_BIO, wbio: SSL_BIO) ---
		SSL_set_tlsext_host_name :: proc(ssl: SSL, name: cstring) -> c.int ---
		SSL_connect :: proc(ssl: SSL) -> c.int ---
		SSL_shutdown :: proc(ssl: SSL) -> c.int ---
		SSL_get_error :: proc(ssl: SSL, ret: c.int) -> c.int ---
		SSL_read :: proc(ssl: SSL, buf: rawptr, num: c.int) -> c.int ---
		SSL_write :: proc(ssl: SSL, buf: rawptr, num: c.int) -> c.int ---
		SSL_pending :: proc(ssl: SSL) -> c.int ---


	}
} else {
	d2i_X509 :: proc(a: ^X509, ppin: ^^c.uchar, length: c.long) -> X509 {return nil}
	X509_STORE_add_cert :: proc(ctx: X509_STORE, x: X509) -> c.int {return 0}
	X509_free :: proc(x: X509) {}

	OPENSSL_version_major :: proc() -> c.uint {return 0}
	OPENSSL_version_minor :: proc() -> c.uint {return 0}
	OPENSSL_version_patch :: proc() -> c.uint {return 0}

	OPENSSL_init_ssl :: proc(opts: c.uint64_t, settings: OPENSSL_INIT_SETTINGS) -> c.int {return 0}

	TLS_client_method :: proc() -> SSL_METHOD {return nil}

	SSL_CTX_new :: proc(method: SSL_METHOD) -> SSL_CTX {return nil}
	SSL_CTX_free :: proc(ctx: SSL_CTX) {}
	SSL_CTX_set_verify :: proc(ctx: SSL_CTX, mode: c.int, verify_callback: SSL_verify_cb) {}
	SSL_CTX_set_verify_depth :: proc(ctx: SSL_CTX, depth: c.int) {}
	SSL_CTX_set_default_verify_paths :: proc(ctx: SSL_CTX) -> c.int {return 0}
	SSL_CTX_get_timeout :: proc(ctx: SSL_CTX) -> c.long {return 0}
	SSL_CTX_set_timeout :: proc(ctx: SSL_CTX, t: c.long) -> c.long {return 0}
	SSL_CTX_get_options :: proc(ctx: SSL_CTX) -> c.uint64_t {return 0}
	SSL_CTX_set_options :: proc(ctx: SSL_CTX, options: c.uint64_t) -> c.uint64_t {return 0}
	SSL_CTX_get_cert_store :: proc(ctx: SSL_CTX) -> X509_STORE {return nil}

	BIO_new_socket :: proc(sock: c.int, close_flag: c.int) -> SSL_BIO {return nil}

	SSL_new :: proc(ctx: SSL_CTX) -> SSL {return nil}
	SSL_free :: proc(ssl: SSL) {}
	SSL_set_bio :: proc(ssl: SSL, rbio: SSL_BIO, wbio: SSL_BIO) {}
	SSL_set_tlsext_host_name :: proc(ssl: SSL, name: cstring) -> c.int {return 0}
	SSL_connect :: proc(ssl: SSL) -> c.int {return 0}
	SSL_shutdown :: proc(ssl: SSL) -> c.int {return 0}
	SSL_get_error :: proc(ssl: SSL, ret: c.int) -> c.int {return 0}
	SSL_read :: proc(ssl: SSL, buf: rawptr, num: c.int) -> c.int {return 0}
	SSL_write :: proc(ssl: SSL, buf: rawptr, num: c.int) -> c.int {return 0}
	SSL_pending :: proc(ssl: SSL) -> c.int {return 0}
}


// ###############################################################################
// What follows is not part of the bindings directly, but helpers for easier usage
// ###############################################################################

when ODIN_OS == .Windows && SSL_SUPPORT {
	import win32 "core:sys/windows"
	foreign import crypt32 "system:crypt32.lib"

	win32_HCRYPTPROV_LEGACY :: distinct win32.HANDLE
	win32_HCERTSTORE :: distinct win32.HANDLE

	win32_CERT_CONTEXT :: struct {
		dwCertEncodingType: win32.DWORD,
		pbCertEncoded:      ^win32.BYTE,
		cbCertEncoded:      win32.DWORD,
		pCertInfo:          win32.DWORD,
		hCertStore:         win32_HCERTSTORE,
	}
	win32_PCCERT_CONTEXT :: distinct ^win32_CERT_CONTEXT

	@(default_calling_convention = "stdcall")
	foreign crypt32 {
		CertOpenSystemStoreW :: proc(
			hProv: win32_HCRYPTPROV_LEGACY,
			szSubsystemProtocol: win32.LPCWSTR,
		) -> win32_HCERTSTORE ---
		CertEnumCertificatesInStore :: proc(
			hCertStore: win32_HCERTSTORE,
			pPrevCertContext: win32_PCCERT_CONTEXT,
		) -> win32_PCCERT_CONTEXT ---
		CertFreeCertificateContext :: proc(pCertContext: win32_PCCERT_CONTEXT) -> win32.BOOL ---
		CertCloseStore :: proc(hCertStore: win32_HCERTSTORE, dwFlags: win32.DWORD) -> win32.BOOL ---
	}

	load_system_certs :: proc(ctx: SSL_CTX) -> bool {
		// code from:
		// here: https://github.com/yhirose/cpp-httplib/blob/v0.10.5/httplib.h
		// and here: https://stackoverflow.com/questions/9507184/can-openssl-on-windows-use-the-system-certificate-store
		ossl_store := SSL_CTX_get_cert_store(ctx)
		lsprotocol := win32.utf8_to_wstring("ROOT")
		win_store := CertOpenSystemStoreW(nil, lsprotocol)

		if ossl_store == nil || win_store == nil {
			return false
		}

		cert_context := CertEnumCertificatesInStore(win_store, nil)
		for ; cert_context != nil; cert_context = CertEnumCertificatesInStore(win_store, cert_context) {
			encoded_cert := cast(^u8)(cert_context.pbCertEncoded)
			x509 := d2i_X509(nil, &encoded_cert, c.long(cert_context.cbCertEncoded))
			if x509 != nil {
				X509_STORE_add_cert(ossl_store, x509)
				X509_free(x509)
			}
		}

		CertFreeCertificateContext(cert_context)
		CertCloseStore(win_store, 0)
		return true
	}
} else when SSL_SUPPORT {
	load_system_certs :: proc(ctx: SSL_CTX) -> bool {
		return SSL_CTX_set_default_verify_paths(ctx) == 1 ? true : false
	}
} else {
	load_system_certs :: proc(ctx: SSL_CTX) -> bool {
		return false
	}
}
