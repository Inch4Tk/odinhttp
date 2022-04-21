package test_http

import "core:testing"
import "core:fmt"
import "core:strings"
import "core:os"
import "core:time"
import json "core:encoding/json"
import http "../http"

TEST_count := 0
TEST_fail := 0

when ODIN_TEST {
	expect :: testing.expect
	log :: testing.log
} else {
	expect :: proc(t: ^testing.T, condition: bool, message: string, loc := #caller_location) {
		TEST_count += 1
		if !condition {
			TEST_fail += 1
			fmt.printf("[%v] %v\n", loc, message)
			return
		}
	}
	log :: proc(t: ^testing.T, v: any, loc := #caller_location) {
		fmt.printf("[%v] ", loc)
		fmt.printf("log: %v\n", v)
	}
}

when http.SSL_SUPPORT {
	SCHEME := "https"
} else {
	SCHEME := "http"
}


sleep :: proc(t: ^testing.T) {
	log(t, "Sleep 1 secs to make sure we are not stressing httpbin.org...")
	time.sleep(time.Second)
}

main :: proc() {
	// TODO: Make a test environment which only does http, but local for fast running tests
	t := testing.T{}

	// Tests are only local
	make_session(&t)
	url_parse(&t)
	request_prepare(&t)

	// Tests make external requests
	get(&t)
	sleep(&t)
	get_chunked(&t)
	sleep(&t)
	get_compression(&t)
	sleep(&t)
	post(&t)
	sleep(&t)
	patch(&t)
	sleep(&t)
	put(&t)
	sleep(&t)
	method_delete(&t)

	fmt.printf("%v/%v tests successful.\n", TEST_count - TEST_fail, TEST_count)
	if TEST_fail > 0 {
		os.exit(1)
	}
}

@(test)
make_session :: proc(t: ^testing.T) {
	sess, err := http.make_session()
	defer http.delete_session(sess)
	expect(t, sess != nil, "expect session to be not empty")
	expect(t, err == .None, "expect error to be none")
}

url_expect :: proc(t: ^testing.T, parsed_url: ^http.Url, expect_url: ^http.Url) {
	b := parsed_url.scheme == expect_url.scheme && parsed_url.hostname == expect_url.hostname && parsed_url.port ==
      expect_url.port && parsed_url.path == expect_url.path && parsed_url.query == expect_url.query &&
      parsed_url.fragment == expect_url.fragment
	expect(
		t,
		b,
		fmt.tprintf("expect parsed url %v to be same as expected url %v", parsed_url, expect_url),
	)
}

@(test)
url_parse :: proc(t: ^testing.T) {
	c_url := http.Url{}

	// Nothing
	c_url.scheme = SCHEME
	c_url.hostname = "foobar.com"
	c_url.port = SCHEME == "http" ? http.HTTP_PORT : http.HTTPS_PORT
	to_parse := http.url_to_tstring(&c_url)
	url, err := http.url_parse(to_parse)
	expect(t, err == .None, "expect url properly parsed")
	url_expect(t, url, &c_url)
	http.url_free(url)

	// Path
	c_url.scheme = SCHEME
	c_url.port = SCHEME == "http" ? http.HTTP_PORT : http.HTTPS_PORT
	c_url.hostname = "foobar.com"
	c_url.path = "/api/something"
	to_parse = http.url_to_tstring(&c_url)
	url, err = http.url_parse(to_parse)
	expect(t, err == .None, "expect url properly parsed")
	url_expect(t, url, &c_url)
	http.url_free(url)

	// Non-default port
	c_url.scheme = SCHEME
	c_url.hostname = "foobar.com"
	c_url.port = 12345
	c_url.path = "/api/something"
	to_parse = http.url_to_tstring(&c_url)
	url, err = http.url_parse(to_parse)
	expect(t, err == .None, "expect url properly parsed")
	url_expect(t, url, &c_url)
	http.url_free(url)

	// Path and query 1
	c_url.scheme = SCHEME
	c_url.hostname = "foobar.com"
	c_url.port = SCHEME == "http" ? http.HTTP_PORT : http.HTTPS_PORT
	c_url.path = "/api/something"
	c_url.query = "qwert=1234"
	to_parse = http.url_to_tstring(&c_url)
	url, err = http.url_parse(to_parse)
	expect(t, err == .None, "expect url properly parsed")
	url_expect(t, url, &c_url)
	http.url_free(url)

	// Path and query 2
	c_url.scheme = SCHEME
	c_url.hostname = "foobar.com"
	c_url.port = SCHEME == "http" ? http.HTTP_PORT : http.HTTPS_PORT
	c_url.path = "/api/something"
	c_url.query = "qwert=1234&vcbdf=432"
	to_parse = http.url_to_tstring(&c_url)
	url, err = http.url_parse(to_parse)
	expect(t, err == .None, "expect url properly parsed")
	url_expect(t, url, &c_url)
	http.url_free(url)

	// Only query
	c_url.scheme = SCHEME
	c_url.hostname = "foobar.com"
	c_url.port = SCHEME == "http" ? http.HTTP_PORT : http.HTTPS_PORT
	c_url.path = ""
	c_url.query = "qwert=1234&vcbdf=432"
	to_parse = http.url_to_tstring(&c_url)
	url, err = http.url_parse(to_parse)
	expect(t, err == .None, "expect url properly parsed")
	url_expect(t, url, &c_url)
	http.url_free(url)

	// path and fragment 1
	c_url.scheme = SCHEME
	c_url.hostname = "foobar.com"
	c_url.port = SCHEME == "http" ? http.HTTP_PORT : http.HTTPS_PORT
	c_url.path = "/api/something/"
	c_url.query = ""
	c_url.fragment = "qwert"
	to_parse = http.url_to_tstring(&c_url)
	url, err = http.url_parse(to_parse)
	expect(t, err == .None, "expect url properly parsed")
	url_expect(t, url, &c_url)
	http.url_free(url)

	// path and fragment 2
	c_url.scheme = SCHEME
	c_url.hostname = "foobar.com"
	c_url.port = SCHEME == "http" ? http.HTTP_PORT : http.HTTPS_PORT
	c_url.path = "/api/something"
	c_url.query = ""
	c_url.fragment = "qwert"
	to_parse = http.url_to_tstring(&c_url)
	url, err = http.url_parse(to_parse)
	expect(t, err == .None, "expect url properly parsed")
	url_expect(t, url, &c_url)
	http.url_free(url)

	// only fragment
	c_url.scheme = SCHEME
	c_url.hostname = "foobar.com"
	c_url.port = SCHEME == "http" ? http.HTTP_PORT : http.HTTPS_PORT
	c_url.path = ""
	c_url.query = ""
	c_url.fragment = "qwert"
	to_parse = http.url_to_tstring(&c_url)
	url, err = http.url_parse(to_parse)
	expect(t, err == .None, "expect url properly parsed")
	url_expect(t, url, &c_url)
	http.url_free(url)

	// path, query and fragment
	c_url.scheme = SCHEME
	c_url.hostname = "foobar.com"
	c_url.port = SCHEME == "http" ? http.HTTP_PORT : http.HTTPS_PORT
	c_url.path = "/api/something"
	c_url.query = "qwert=1234&vcbdf=432"
	c_url.fragment = "qwert"
	to_parse = http.url_to_tstring(&c_url)
	url, err = http.url_parse(to_parse)
	expect(t, err == .None, "expect url properly parsed")
	url_expect(t, url, &c_url)
	http.url_free(url)

	// path, query and fragment, nonstandard port
	c_url.scheme = SCHEME
	c_url.hostname = "foobar.com"
	c_url.port = 32456
	c_url.path = "/api/something"
	c_url.query = "qwert=1234&vcbdf=432"
	c_url.fragment = "qwert"
	to_parse = http.url_to_tstring(&c_url)
	url, err = http.url_parse(to_parse)
	expect(t, err == .None, "expect url properly parsed")
	url_expect(t, url, &c_url)
	http.url_free(url)

	// manual url, not by url_to_tstring as sanity check
	to_parse = "http://asdfasdf.xyx?qwert=1234"
	url, err = http.url_parse(to_parse)
	expect(t, err == .None, "expect url properly parsed")
	expect(t, url.hostname == "asdfasdf.xyx", "expect url properly parsed")
	expect(t, url.scheme == "http", "expect url properly parsed")
	expect(t, url.query == "qwert=1234", "expect url properly parsed")
	expect(t, url.path == "", "expect url properly parsed")
	expect(t, url.fragment == "", "expect url properly parsed")
	http.url_free(url)

	// failure on wrong schema
	to_parse = "wss://asdfasdf.xyx/dkjfd"
	url, err = http.url_parse(to_parse)
	expect(t, err == .Url_Invalid_Scheme, "expect url to declare invalid SCHEME")
	http.url_free(url)
}

@(test)
request_prepare :: proc(t: ^testing.T) {
	req, error := http.request_prepare(http.Http_Method.Get, "http://httpbin.org/get")
	expect(t, error == .None, "expect error to be none")
	http.request_delete(req)

	headers := make(map[string]string)
	token := "qwerasdf"
	headers["authorization"] = fmt.tprintf("Bearer %s", token)
	headers["accept-encoding"] = "identity"
	headers["connection"] = "close"
	headers["content-type"] = "application/json"

	cookies := make(map[string]string)
	cookies["some_random_cookie"] = "with_random_value"

	json_body := make(map[string]int)
	json_body["key1"] = 0
	json_body["key2"] = 123
	json_body["key3"] = 987
	body_data := json.marshal(json_body) or_else []u8{}

	req, error = http.request_prepare(
		method = .Post,
		url = "https://httpbin.org/post",
		headers = headers,
		cookies = cookies,
		body_data = body_data,
		timeout_ms = 3000,
	)
	expect(t, error == .None, "expect error to be none")
	delete(cookies)
	delete(headers)
	delete(json_body)
	http.request_delete(req)
}

@(test)
get :: proc(t: ^testing.T) {
	sess, err := http.make_session()
	defer http.delete_session(sess)
	expect(t, err == .None, "expect error to be none")

	// simple get always http
	req: ^http.Request;res: ^http.Response
	req, err = http.request_prepare(http.Http_Method.Get, "http://httpbin.org/get")
	expect(t, err == .None, "expect error to be none")
	res, err = http.request(sess, req)
	expect(t, err == .None, "expect error to be none")
	res_json_body := json.parse(res.body) or_else nil
	expect(t, res_json_body != nil, "expect response to not be empty")
	body_map, ok := res_json_body.(json.Object)
	expect(t, ok && body_map["url"].(string) == "http://httpbin.org/get", "expect response to not be empty")

	json.destroy_value(res_json_body)
	http.request_delete(req)
	http.response_delete(res)

	// simple get
	url := fmt.tprintf("%s://httpbin.org/get", SCHEME)
	req, err = http.request_prepare(http.Http_Method.Get, url)
	expect(t, err == .None, "expect error to be none")
	res, err = http.request(sess, req)
	expect(t, err == .None, "expect error to be none")
	res_json_body = json.parse(res.body) or_else nil
	expect(t, res_json_body != nil, "expect response to not be empty")
	body_map, ok = res_json_body.(json.Object)
	expect(t, ok && body_map["url"].(string) == url, "expect response to not be empty")

	json.destroy_value(res_json_body)
	http.request_delete(req)
	http.response_delete(res)

	// /json
	url = fmt.tprintf("%s://httpbin.org/json", SCHEME)
	req, err = http.request_prepare(http.Http_Method.Get, url)
	expect(t, err == .None, "expect error to be none")
	res, err = http.request(sess, req)
	expect(t, err == .None, "expect error to be none")
	res_json_body = json.parse(res.body) or_else nil
	expect(t, res_json_body != nil, "expect response to not be empty")
	body_map, ok = res_json_body.(json.Object)
	expect(t, ok, "expect response to not be empty and be a valid json object")
	body_map, ok = body_map["slideshow"].(json.Object)
	expect(t, ok, "expect json body to contain 'slideshow' subobject")
	expect(t, body_map["author"].(string) == "Yours Truly", "expect slideshow to have author value")
	expect(t, body_map["date"].(string) == "date of publication", "expect slideshow to have date value")
	expect(t, body_map["slides"].(json.Array) != nil, "expect slideshow to have slides value")
	expect(t, body_map["title"].(string) == "Sample Slide Show", "expect slideshow to have title value")

	json.destroy_value(res_json_body)
	http.request_delete(req)
	http.response_delete(res)

}

@(test)
get_chunked :: proc(t: ^testing.T) {
	sess, err := http.make_session()
	defer http.delete_session(sess)
	expect(t, err == .None, "expect error to be none")

	url := fmt.tprintf("%s://httpbin.org/stream/10", SCHEME)
	req: ^http.Request; res: ^http.Response;
	req, err = http.request_prepare(http.Http_Method.Get, url)
	expect(t, err == .None, "expect error to be none")
	res, err = http.request(sess, req)
	expect(t, err == .None, "expect error to be none")
	expect(t, res.headers["transfer-encoding"] == "chunked", "expect response header transfer-encoding to be chunked")
	// Note: This is not the typical behavior of chunked, but the response json body
	// of httpbin is ill-formed. It sends the full body in each chunk instead of sending part
	// of the body each chunk.
	bodies := strings.split(string(res.body), "\n")
	for body in bodies {
		res_json_body := json.parse(res.body) or_else nil
		expect(t, res_json_body != nil, "expect response body to not be empty")
		body_map, ok := res_json_body.(json.Object)
		expect(t, ok, "expect response to not be empty and be a valid json object")
		expect(t, body_map["url"].(string) == url, "expect response body to contain right url")
		json.destroy_value(res_json_body)
	}

	delete(bodies)
	http.request_delete(req)
	http.response_delete(res)
}

@(test)
get_compression :: proc(t: ^testing.T) {
	sess, err := http.make_session()
	defer http.delete_session(sess)
	expect(t, err == .None, "expect error to be none")

	// /deflate
	url := fmt.tprintf("%s://httpbin.org/deflate", SCHEME)
	req: ^http.Request; res: ^http.Response;
	req, err = http.request_prepare(http.Http_Method.Get, url)
	expect(t, err == .None, "expect error to be none")
	res, err = http.request(sess, req)
	expect(t, err == .None, "expect error to be none")
	res_json_body := json.parse(res.body) or_else nil
	expect(t, res_json_body != nil, "expect response to not be empty")
	body_map, ok := res_json_body.(json.Object)
	expect(t, ok, "expect response to not be empty and be a valid json object")
	expect(t, body_map["deflated"].(bool) == true, "expect response body to contain deflated")
	expect(t, res.headers["content-encoding"] == "deflate", "expect response header content-encoding to be deflated")

	json.destroy_value(res_json_body)
	http.request_delete(req)
	http.response_delete(res)

	// /gzip
	url = fmt.tprintf("%s://httpbin.org/gzip", SCHEME)
	req, err = http.request_prepare(http.Http_Method.Get, url)
	expect(t, err == .None, "expect error to be none")
	res, err = http.request(sess, req)
	expect(t, err == .None, "expect error to be none")
	res_json_body = json.parse(res.body) or_else nil
	expect(t, res_json_body != nil, "expect response to not be empty")
	body_map, ok = res_json_body.(json.Object)
	expect(t, ok, "expect response to not be empty and be a valid json object")
	expect(t, body_map["gzipped"].(bool) == true, "expect response body to contain gzip")
	expect(t, res.headers["content-encoding"] == "gzip", "expect response header content-encoding to be gzip")

	json.destroy_value(res_json_body)
	http.request_delete(req)
	http.response_delete(res)
}


@(test)
post :: proc(t: ^testing.T) {
	sess, err := http.make_session()
	defer http.delete_session(sess)
	expect(t, err == .None, "expect error to be none")

	headers := make(map[string]string)
	token := "qwerasdf"
	bearer := fmt.aprintf("Bearer %s", token)
	defer delete(bearer)
	headers["authorization"] = bearer
	headers["content-type"] = "application/json"

	cookies := make(map[string]string)
	cookies["some_random_cookie"] = "with_random_value"

	json_body := make(map[string]int)
	json_body["key1"] = 0
	json_body["key2"] = 123
	json_body["key3"] = 987
	body_data := json.marshal(json_body) or_else []u8{}

	url := fmt.tprintf("%s://httpbin.org/post", SCHEME)
	req: ^http.Request; res: ^http.Response;
	req, err = http.request_prepare(
		method = .Post,
		url = url,
		headers = headers,
		cookies = cookies,
		body_data = body_data,
		timeout_ms = 3000,
	)
	expect(t, err == .None, "expect error to be none")

	res, err = http.request(sess, req)
	expect(t, err == .None, "expect error to be none")
	res_json_body := json.parse(res.body) or_else nil
	expect(t, res_json_body != nil, "expect response to not be empty")
	body_map, ok := res_json_body.(json.Object)
	expect(t, ok && body_map["url"].(string) == url, "expect response to not be empty")
	expect(t, body_map["json"].(json.Object) != nil, "expect response to contain a json request object")
	expect(t, body_map["headers"].(json.Object)["Authorization"].(string) == bearer, "expect response to contain the same auth header in body")

	delete(cookies)
	delete(headers)
	delete(json_body)
	http.request_delete(req)
	http.response_delete(res)
}

@(test)
patch :: proc(t: ^testing.T) {
	sess, err := http.make_session()
	defer http.delete_session(sess)
	expect(t, err == .None, "expect error to be none")

	headers := make(map[string]string)
	token := "qwerasdf"
	bearer := fmt.aprintf("Bearer %s", token)
	defer delete(bearer)
	headers["authorization"] = bearer
	headers["content-type"] = "application/json"

	cookies := make(map[string]string)
	cookies["some_random_cookie"] = "with_random_value"

	json_body := make(map[string]int)
	json_body["key1"] = 0
	json_body["key2"] = 123
	json_body["key3"] = 987
	body_data := json.marshal(json_body) or_else []u8{}

	url := fmt.tprintf("%s://httpbin.org/patch", SCHEME)
	req: ^http.Request; res: ^http.Response;
	req, err = http.request_prepare(
		method = .Patch,
		url = url,
		headers = headers,
		cookies = cookies,
		body_data = body_data,
		timeout_ms = 3000,
	)
	expect(t, err == .None, "expect error to be none")

	res, err = http.request(sess, req)
	expect(t, err == .None, "expect error to be none")
	res_json_body := json.parse(res.body) or_else nil
	expect(t, res_json_body != nil, "expect response to not be empty")
	body_map, ok := res_json_body.(json.Object)
	expect(t, ok && body_map["url"].(string) == url, "expect response to not be empty")
	expect(t, body_map["json"].(json.Object) != nil, "expect response to contain a json request object")
	expect(t, body_map["headers"].(json.Object)["Authorization"].(string) == bearer, "expect response to contain the same auth header in body")

	delete(cookies)
	delete(headers)
	delete(json_body)
	http.request_delete(req)
	http.response_delete(res)
}

@(test)
put :: proc(t: ^testing.T) {
	sess, err := http.make_session()
	defer http.delete_session(sess)
	expect(t, err == .None, "expect error to be none")

	headers := make(map[string]string)
	token := "qwerasdf"
	bearer := fmt.aprintf("Bearer %s", token)
	defer delete(bearer)
	headers["authorization"] = bearer
	headers["content-type"] = "application/json"

	cookies := make(map[string]string)
	cookies["some_random_cookie"] = "with_random_value"

	json_body := make(map[string]int)
	json_body["key1"] = 0
	json_body["key2"] = 123
	json_body["key3"] = 987
	body_data := json.marshal(json_body) or_else []u8{}

	url := fmt.tprintf("%s://httpbin.org/put", SCHEME)
	req: ^http.Request; res: ^http.Response;
	req, err = http.request_prepare(
		method = .Put,
		url = url,
		headers = headers,
		cookies = cookies,
		body_data = body_data,
		timeout_ms = 3000,
	)
	expect(t, err == .None, "expect error to be none")

	res, err = http.request(sess, req)
	expect(t, err == .None, "expect error to be none")
	res_json_body := json.parse(res.body) or_else nil
	expect(t, res_json_body != nil, "expect response to not be empty")
	body_map, ok := res_json_body.(json.Object)
	expect(t, ok && body_map["url"].(string) == url, "expect response to not be empty")
	expect(t, body_map["json"].(json.Object) != nil, "expect response to contain a json request object")
	expect(t, body_map["headers"].(json.Object)["Authorization"].(string) == bearer, "expect response to contain the same auth header in body")

	delete(cookies)
	delete(headers)
	delete(json_body)
	http.request_delete(req)
	http.response_delete(res)
}

@(test)
method_delete :: proc(t: ^testing.T) {
	sess, err := http.make_session()
	defer http.delete_session(sess)
	expect(t, err == .None, "expect error to be none")

	headers := make(map[string]string)
	token := "qwerasdf"
	bearer := fmt.aprintf("Bearer %s", token)
	defer delete(bearer)
	headers["authorization"] = bearer
	headers["content-type"] = "application/json"

	cookies := make(map[string]string)
	cookies["some_random_cookie"] = "with_random_value"

	json_body := make(map[string]int)
	json_body["key1"] = 0
	json_body["key2"] = 123
	json_body["key3"] = 987
	body_data := json.marshal(json_body) or_else []u8{}

	url := fmt.tprintf("%s://httpbin.org/delete", SCHEME)
	req: ^http.Request; res: ^http.Response;
	req, err = http.request_prepare(
		method = .Delete,
		url = url,
		headers = headers,
		cookies = cookies,
		body_data = body_data,
		timeout_ms = 3000,
	)
	expect(t, err == .None, "expect error to be none")

	res, err = http.request(sess, req)
	expect(t, err == .None, "expect error to be none")
	res_json_body := json.parse(res.body) or_else nil
	expect(t, res_json_body != nil, "expect response to not be empty")
	body_map, ok := res_json_body.(json.Object)
	expect(t, ok && body_map["url"].(string) == url, "expect response to not be empty")
	expect(t, body_map["json"].(json.Object) != nil, "expect response to contain a json request object")
	expect(t, body_map["headers"].(json.Object)["Authorization"].(string) == bearer, "expect response to contain the same auth header in body")

	delete(cookies)
	delete(headers)
	delete(json_body)
	http.request_delete(req)
	http.response_delete(res)
}
