package httparser

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"unicode"
)

var (
	ErrHTTPVersion     = errors.New("http version")
	ErrHTTPVersionNum  = errors.New("http version number")
	ErrHTTPStatus      = errors.New("http status")
	ErrRspStatusLine   = errors.New("http rsp status line")
	ErrHeaderOverflow  = errors.New("http header overflow")
	ErrNoEndLF         = errors.New("http there is no end symbol")
	ErrChunkSize       = errors.New("http wrong chunk size")
	ErrTrailerPart     = errors.New("http trailer-part is not supported")
	ErrReqMethod       = errors.New("http request wrong method")
	ErrRequestLineCRLF = errors.New("http request line wrong CRLF")
)

var (
	strTTPslash = []byte("TTP/")
)

var (
	contentLength          = []byte("Content-Length")
	transferEncoding       = []byte("Transfer-Encoding")
	chunked                = []byte("chunked")
	maxHeaderSize    int32 = 4096 //默认http header单行最大限制为4k
)

// Request .
type Request struct {
	Status  string
	URL     *url.URL
	Headers map[string]string
	Body    []byte
}

// http 1.1 or http 1.0解析器
type Parser struct {
	currState           state       //记录当前状态
	headerCurrState     headerState //记录http field状态
	major               uint8       //主版本号
	minor               uint8       //次版本号
	maxHeaderSize       int32       //最大头长度
	contentLength       int32       //content-length 值
	StatusCode          uint16      //状态码
	hasContentLength    bool        //设置Content-Length头部
	hasTransferEncoding bool        //transferEncoding头部

	buffer      []byte
	request     *Request
	headerField string
}

// 解析器构造函数
func New(t ReqOrRsp) *Parser {
	p := &Parser{}
	p.Init(t)
	return p
}

// 解析器Init函数
func (p *Parser) Init(t ReqOrRsp) {
	switch t {
	case REQUEST:
		p.currState = startReq
	case RESPONSE:
		p.currState = startRsp
	case BOTH:
		p.currState = startReqOrRsp
	}

	p.major = 0
	p.minor = 0
	p.maxHeaderSize = maxHeaderSize

}

// Execute传递setting参数, 该API 设计成现有形式有如下原因:
// setting如果通过New函数传递, Parser内存占用会多8 * 6的byte
// 为了减小Parser的大小，setting放至Execute函数里面传递

// 请求报文示例
// GET /somedir/page.html HTTP/1.1
// Host: www.someschool.edu
// Connection: close
// User-agent: Mozilla/5.0
// Accept-language: fr

// 响应报文示例
// HTTP/1.1   200   OK
// Connection: close
// Date: Tue,  09 Aug  2011  15:44:04 GMT
// Server: Apache/2.2.3 (CentOS)
// Last-Modified: Tue, 09 Aug 2011 15:11:03 GMT
// Content-Length: 6821
// Content-Type: text/html

// 响应行
// https://tools.ietf.org/html/rfc7230#section-3.1.2 状态行
// status-line = HTTP-version SP status-code SP reason-phrase CRLF

// 请求行
// https://tools.ietf.org/html/rfc7230#section-3.1.1
// method SP request-target SP HTTP-version CRLF

// 设计思路修改
// 为了适应流量解析的场景，状态机的状态会更碎一点

func (p *Parser) Read(buf []byte) {
	p.buffer = append(p.buffer, buf...)
}

func (p *Parser) Execute(setting *Setting) (*Request, bool, error) {
	var (
		err                 error
		currState           = p.currState
		chunkDataStartIndex = 0
		urlStartIndex       = 0
	)

	// for j := 0; j < len(p.buffers); j++ {
	buf := p.buffer

	i := 0
	c := byte(0)

	for ; i < len(buf); i++ {
		c = buf[i]

	reExec:
		switch currState {
		case startReqOrRsp:
			if c == 'H' {
				if setting.MessageBegin != nil {
					setting.MessageBegin()
				}
				if p.request == nil {
					p.request = &Request{}
				}
				currState = rspHTTP
				continue
			}
			currState = startReq
			fallthrough
		case startReq:
			if token[c] == 0 {
				return nil, false, ErrReqMethod
			}

			currState = reqMethod
			if setting.MessageBegin != nil {
				setting.MessageBegin()
			}
			if p.request == nil {
				p.request = &Request{}
			}

		case reqMethod:
			if token[c] == 0 {
				if c == ' ' || c == '\t' {
					currState = reqMethodAfterSP
					continue
				}

				return nil, false, ErrReqMethod
			}

			// 维持reqMethod状态不变
		case reqMethodAfterSP:
			if c != ' ' && c != '\t' {
				urlStartIndex = i
				currState = reqURL
			}

		case reqURL:
			if c == ' ' || c == '\t' {
				currState = reqURLAfterSP
				if setting.URL != nil {
					setting.URL(buf[urlStartIndex:i])
				}
				p.request.URL, err = url.Parse(string(buf[urlStartIndex:i]))
				if err != nil {
					return nil, false, err
				}
			}

		case reqURLAfterSP:
			if c != ' ' && c != '\t' {
				currState = reqHTTPVersion
			}
		case reqHTTPVersion:
			if c == '\r' {
				currState = reqRequestLineAlomstDone
			}

		case reqRequestLineAlomstDone:
			if c != '\n' {
				return nil, false, ErrRequestLineCRLF
			}

			currState = headerField

		case startRsp:
			if c != 'H' {
				return nil, false, ErrHTTPVersion
			}

			if setting.MessageBegin != nil {
				setting.MessageBegin()
			}

			currState = rspHTTP

		case rspHTTP:
			if len(buf[i:]) < len(strTTPslash) {
				return nil, false, ErrHTTPVersion
			}

			if !bytes.Equal(buf[i:len(strTTPslash)+1], strTTPslash) {
				return nil, false, ErrHTTPVersion
			}

			i += len(strTTPslash) - 1
			currState = rspHTTPVersionNum

		case rspHTTPVersionNum:
			// 1.1 or 1.0 or 0.9
			if len(buf[i:]) < 3 || !unicode.IsNumber(rune(buf[i])) || !unicode.IsNumber(rune(buf[i+2])) {
				return nil, false, ErrHTTPVersionNum
			}

			p.major = buf[i] - '0'
			p.minor = buf[i+2] - '0'
			i += 2 // 3-1
			currState = rspStatusCode

		case rspStatusCode:
			for ; i < len(buf) && (buf[i] == ' ' || buf[i] == '\r' || buf[i] == '\n'); i++ {
			}

			for ; i < len(buf) && buf[i] >= '0' && buf[i] <= '9'; i++ {
				p.StatusCode = uint16(int(p.StatusCode)*10 + int(buf[i]-'0'))
			}

			if i >= len(buf) {
				return nil, false, ErrHTTPStatus
			}

			currState = rspStatus
			goto reExec
		case rspStatus:
			start := i

			// bytes.IndexAny()
			for ; start < len(buf) && (buf[start] == ' ' || buf[start] == '\r' || buf[start] == '\n'); start++ {
			}

			end := start
			for ; end < len(buf) && !(buf[end] == ' ' || buf[end] == '\r' || buf[end] == '\n'); end++ {
			}

			if end >= len(buf) || end+1 >= len(buf) {
				return nil, false, ErrRspStatusLine
			}

			//TODO单独状态
			switch {
			case buf[end] == '\r' && buf[end+1] == '\n':
				i = end + 1
			case buf[end] == '\r' || buf[end] == '\n':
				i = end
			}

			if setting.Status != nil {
				setting.Status(buf[start:end])
			}
			p.request.Status = string(buf[start:end])

			currState = headerField

		case headerField:
			if c == '\r' || c == '\n' {
				currState = headerDone
				continue
			}

			pos := bytes.IndexByte(buf[i:], ':')
			if pos == -1 {
				if int32(len(buf[i:])) > p.maxHeaderSize {
					return nil, false, ErrHeaderOverflow
				}

				p.currState = headerField
				return nil, false, nil
			}

			field := buf[i : i+pos]
			if setting.HeaderField != nil {
				setting.HeaderField(field)
			}
			p.headerField = string(field)

			c2 := c | 0x20
			if c2 == 'c' || c2 == 't' {
				if bytes.Equal(field, contentLength) {
					// Content-Length
					p.headerCurrState = hContentLength
				} else if bytes.Equal(field, transferEncoding) {
					// Transfer-Encoding
					p.headerCurrState = hTransferEncoding
				} else {
					// general
					p.headerCurrState = hGeneral
				}
			} else {
				p.headerCurrState = hGeneral
			}

			i += pos
			currState = headerValueDiscardWs
		case headerValueDiscardWs:
			// 只跳过一个' ' or '\t'
			currState = headerValue
			if c == ' ' || c == '\t' {
				continue
			}

			// 解析http value
		case headerValue:
			end := bytes.IndexAny(buf[i:], "\r\n")
			if end == -1 {
				if int32(len(buf[i:])) > p.maxHeaderSize {
					return nil, false, ErrHeaderOverflow
				}
				p.currState = headerValueDiscardWs
				return nil, false, nil
			}

			if setting.HeaderValue != nil {
				setting.HeaderValue(buf[i : i+end])
			}
			if p.request.Headers == nil {
				p.request.Headers = map[string]string{}
			}
			p.request.Headers[p.headerField] = string(buf[i : i+end])

			switch p.headerCurrState {
			case hContentLength:
				n, err := strconv.Atoi(BytesToString(buf[i : i+end]))
				if err != nil {
					return nil, false, err
				}

				p.contentLength = int32(n)
				p.hasContentLength = true
				p.headerCurrState = hGeneral
			case hTransferEncoding:
				pos := bytes.Index(buf[i:i+end], chunked)
				// 没有chunked值，归类到通用http header
				if pos == -1 {
					p.headerCurrState = hGeneral
				}
				p.hasTransferEncoding = true
			}

			i += end

			c = buf[i]
			currState = headerValueStartOWS
			// 进入header value的OWS
			fallthrough
		case headerValueStartOWS:
			if c == '\r' {
				currState = headerValueOWS
				continue
			}

			// 不是'\r'的情况，继续往下判断
			fallthrough
		case headerValueOWS:
			currState = headerField
			if c == '\n' {
				continue
			}

			// 不是'\n'也许是headerField的数据
			goto reExec

		case headerDone:
			if c != '\n' {
				return nil, false, ErrNoEndLF
			}

			if setting.HeadersComplete != nil {
				setting.HeadersComplete()
			}

			// TODO hasContentLength, hasTransferEncoding同时为true
			if p.hasContentLength {
				// 如果contentLength 等于0，说明body的内容为空，可以直接退出
				if p.contentLength == 0 {
					if setting.MessageComplete != nil {
						setting.MessageComplete()
					}
					p.buffer = p.buffer[i+1:]
					r := p.request
					p.request = nil
					p.Reset()
					return r, true, nil
				}
				currState = httpBody
				continue
			}

			if p.hasTransferEncoding {
				currState = chunkedSizeStart
			}

		case httpBody:
			if p.hasContentLength {
				nread := min(int32(len(buf[i:])), p.contentLength)
				if setting.Body != nil && nread > 0 {
					setting.Body(buf[i : int32(i)+nread])
				}
				p.request.Body = buf[i : int32(i)+nread]

				p.contentLength -= nread

				if p.contentLength == 0 {
					currState = messageDone
				}

				i += int(nread)
			}

		case chunkedSizeStart:
			l := unhex[c]
			if l == -1 {
				return nil, false, ErrChunkSize
			}

			p.contentLength = int32(l)
			currState = chunkedSize

		case chunkedSize:
			if c == '\r' {
				currState = chunkedSizeAlmostDone
				continue
			}

			l := unhex[c]
			if l == -1 {
				if c == ';' {
					currState = chunkedExt
					continue
				}

				return nil, false, ErrChunkSize
			}

			p.contentLength = p.contentLength*16 + int32(l)

		case chunkedExt:
			// 忽略chunked ext
			if c == '\r' {
				currState = chunkedSizeAlmostDone
			}

		case chunkedSizeAlmostDone:
			if p.contentLength == 0 {

				//fmt.Printf("--->%d:%x:(%s)\n", buf[i], buf[i], buf[i:])
				// return nil, false, ErrTrailerPart

				if setting.MessageComplete != nil {
					setting.MessageComplete()
				}
				currState = messageDone

				p.buffer = p.buffer[i+1:]
				r := p.request
				p.request = nil
				p.Reset()
				return r, true, nil

				// continue
			}

			chunkDataStartIndex = i + 1
			currState = chunkedData

		case chunkedData:
			nread := min(int32(len(buf[i:])), p.contentLength)
			if setting.Body != nil && nread > 0 {
				setting.Body(buf[chunkDataStartIndex : int32(chunkDataStartIndex)+nread])
			}
			p.request.Body = buf[i : int32(i)+nread]

			p.contentLength -= nread

			if p.contentLength == 0 {
				currState = chunkedDataAlmostDone
			}

			if nread > 0 {
				i += int(nread) - 1
			}
		case chunkedDataAlmostDone:
			currState = chunkedDataDone
		case chunkedDataDone:
			currState = chunkedSizeStart
		case messageDone:
			// 规范的chunked包是以\r\n结尾的
			if c == '\r' || c == '\n' {
				continue
			}

			currState = startReqOrRsp
			p.Reset()
			goto reExec
		}

	}
	// }
	p.currState = currState
	if currState == messageDone {
		p.buffer = nil
		r := p.request
		p.request = nil
		p.Reset()
		return r, true, nil
	}

	fmt.Println("xxxxx")
	return nil, false, nil
}

func (p *Parser) SetMaxHeaderSize(size int32) {
	p.maxHeaderSize = size
}

func (p *Parser) Reset() {
	p.currState = startReqOrRsp
	p.headerCurrState = hGeneral
	p.major = 0
	p.minor = 0
	//p.maxHeaderSize
	p.contentLength = 0
	p.StatusCode = 0
	p.hasContentLength = false
	p.hasTransferEncoding = false
}

// debug专用
func (p *Parser) Status() string {
	return stateTab[p.currState]
}

func (p *Parser) Eof() bool {
	return p.currState == messageDone
}

func min(a, b int32) int32 {
	if a <= b {
		return a
	}
	return b
}
