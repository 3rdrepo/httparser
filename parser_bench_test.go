package httparser

import "testing"

var data = []byte(
	"POST /joyent/http-parser HTTP/1.1\r\n" +
		"Host: github.com\r\n" +
		"DNT: 1\r\n" +
		"Accept-Encoding: gzip, deflate, sdch\r\n" +
		"Accept-Language: ru-RU,ru;q=0.8,en-US;q=0.6,en;q=0.4\r\n" +
		"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) " +
		"AppleWebKit/537.36 (KHTML, like Gecko) " +
		"Chrome/39.0.2171.65 Safari/537.36\r\n" +
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9," +
		"image/webp,*/*;q=0.8\r\n" +
		"Referer: https://github.com/joyent/http-parser\r\n" +
		"Connection: keep-alive\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Cache-Control: max-age=0\r\n\r\nb\r\nhello world\r\n0\r\n")

var setting = Setting{
	MessageBegin:    func() {},
	URL:             func([]byte) {},
	Status:          func([]byte) {},
	HeaderField:     func([]byte) {},
	HeaderValue:     func([]byte) {},
	HeadersComplete: func() {},
	Body:            func([]byte) {},
	MessageComplete: func() {},
	MessageEnd:      func() {},
}

func Benchmark_Parser(b *testing.B) {

	p := New(REQUEST)

	for i := 0; i < b.N; i++ {
		p.Execute(&setting, data)
		p.Reset()
	}
}
