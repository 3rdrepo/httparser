# httparser
高性能http 1.1解析器，为你的异步io库插上解析的翅膀[从零实现]

## parser request
```go
func main() {
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
		MessageBegin: func() {
		},
		URL: func(buf []byte) {
		},
		Status: func([]byte) {
			// 响应包才需要用到
		},
		HeaderField: func(buf []byte) {
		},
		HeaderValue: func(buf []byte) {
		},
		HeadersComplete: func() {
		},
		Body: func(buf []byte) {
		},
		MessageComplete: func() {
		},
		MessageEnd: func() {
		},
	}

	p := httparser.New(REQUEST)
	i, err := p.Execute(&setting, data)
}
```
