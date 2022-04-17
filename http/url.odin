package http

import "core:strings"
import "core:strconv"

SCHEME_CHARS :: "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789" + "+-."
Url :: struct {
    scheme:   string,
    hostname: string,
    port:     u16,
    path:     string,
    query:    string,
    fragment: string,
}

url_free :: proc(url: ^Url) {
    delete(url.scheme)
    delete(url.hostname)
    delete(url.path)
    delete(url.query)
    delete(url.fragment)
    free(url)
}

// Accepts a string Url and parses it into separate url components.
//
// Allocates the contents of Url struct as necessary. The returned Url can be freed with url_free()
// Make sure to use url_free() on the returned url, even if Url_Parsing_Error is not None
//
// Loosely based on https://github.com/python/cpython/blob/f5542ecf6d340eaaf86f31d90a7a7ff7a99f25a2/Lib/urllib/parse.py#L437
url_parse :: proc(to_parse: string, default_scheme: string = "https") -> (^Url, Request_Preparation_Error) {
    to_parse_s := to_parse[:]
    url := new(Url)

    colon := strings.index_rune(to_parse_s, ':')
    if colon > 0 {
        // Check for illegal characters
        for c in to_parse_s[:colon] {
            if strings.contains_rune(SCHEME_CHARS, c) == -1 {
                return url, .Url_Invalid_Scheme
            }
        }
        // If none were found, split on :
        url.scheme = strings.to_lower(to_parse_s[:colon])
        to_parse_s = to_parse_s[colon + 1:]
    } else {
        url.scheme = strings.clone(default_scheme)
    }
    if url.scheme != "http" && url.scheme != "https" {
        return url, .Url_Invalid_Scheme
    }

    if to_parse_s[:2] == "//" {
        to_parse_s = to_parse_s[2:]
    }
    // Look for delimiters in url
    delim := len(to_parse_s)
    for c in "/?#" {
        delim_pos := strings.index_rune(to_parse_s, c)
        if delim_pos >= 0 {
            delim = min(delim, delim_pos)
        }
    }
    domain := to_parse_s[:delim]
    to_parse_s = to_parse_s[delim:]

    // Check for problems with ipv6 formulation
    obracket := strings.contains_rune(domain, '[') >= 0
    cbracket := strings.contains_rune(domain, ']') >= 0
    if (obracket && !cbracket) || (!obracket && cbracket) {
        return url, .Url_Invalid_Ipv6
    }

    // Check for port in domain
    if strings.contains_rune(domain, ':') >= 0 {
        splits := strings.split_n(domain, ":", 2)
        defer delete(splits)
        domain = splits[0]
        port, ok := strconv.parse_uint(splits[1])
        if !ok || port > 65535 {
            return url, .Url_Invalid_Port
        }
        url.port = u16(port)
    } else if url.scheme == "http" {
        url.port = HTTP_PORT
    } else if url.scheme == "https" {
        url.port = HTTPS_PORT
    }

    // Check for fragments in rest of url
    if strings.contains_rune(to_parse_s, '#') >= 0 {
        splits := strings.split_n(to_parse_s, "#", 2)
        defer delete(splits)
        to_parse_s = splits[0]
        url.fragment = strings.clone(splits[1])
    }

    // Check for query in rest of url
    if strings.contains_rune(to_parse_s, '?') >= 0 {
        splits := strings.split_n(to_parse_s, "?", 2)
        defer delete(splits)
        to_parse_s = splits[0]
        url.query = strings.clone(splits[1])
    }

    url.hostname = strings.to_lower(domain)
    url.path = strings.clone(to_parse_s)
    return url, .None
}
