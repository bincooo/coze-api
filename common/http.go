package common

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

type R struct {
	url     string
	method  string
	proxies string
	headers map[string]string
	query   []string
	bytes   []byte
	err     error
}

func New() *R {
	return &R{
		method:  http.MethodGet,
		query:   make([]string, 0),
		headers: make(map[string]string),
	}
}

func (r *R) URL(value string) *R {
	r.url = value
	return r
}

func (r *R) Method(method string) *R {
	r.method = method
	return r
}

func (r *R) Proxies(proxies string) *R {
	r.proxies = proxies
	return r
}

func (r *R) JsonHeader() *R {
	r.headers["content-type"] = "application/json"
	return r
}

func (r *R) Header(key, value string) *R {
	r.headers[key] = value
	return r
}

func (r *R) Query(key, value string) *R {
	r.query = append(r.query, fmt.Sprintf("%s=%s", key, value))
	return r
}

func (r *R) SetBody(payload interface{}) *R {
	if r.err != nil {
		return r
	}
	r.bytes, r.err = json.Marshal(payload)
	return r
}

func (r *R) SetBytes(data []byte) *R {
	r.bytes = data
	return r
}

func (r *R) Do() (*http.Response, error) {
	if r.err != nil {
		return nil, r.err
	}

	if r.url == "" {
		return nil, errors.New("url cannot be nil, please execute func URL(url string)")
	}

	c, err := client(r.proxies)
	if err != nil {
		return nil, err
	}

	query := ""
	if len(r.query) > 0 {
		var slice []string
		for _, value := range r.query {
			slice = append(slice, value)
		}
		query = "?" + strings.Join(slice, "&")
	}
	request, err := http.NewRequest(r.method, r.url+query, bytes.NewBuffer(r.bytes))
	if err != nil {
		return nil, err
	}

	h := request.Header
	for k, v := range r.headers {
		h.Add(k, v)
	}

	response, err := c.Do(request)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func client(proxies string) (*http.Client, error) {
	c := http.DefaultClient
	if proxies != "" {
		proxiesUrl, err := url.Parse(proxies)
		if err != nil {
			return nil, err
		}

		if proxiesUrl.Scheme == "http" || proxiesUrl.Scheme == "https" {
			c = &http.Client{
				Transport: &http.Transport{
					Proxy: http.ProxyURL(proxiesUrl),
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
			}
		}

		// socks5://127.0.0.1:7890
		if proxiesUrl.Scheme == "socks5" {
			c = &http.Client{
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						dialer, e := proxy.SOCKS5("tcp", proxiesUrl.Host, nil, proxy.Direct)
						if e != nil {
							return nil, e
						}
						return dialer.Dial(network, addr)
					},
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
			}
		}
	}

	return c, nil
}

func ToObj(response *http.Response, obj interface{}) error {
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if err = json.Unmarshal(data, obj); err != nil {
		return err
	}

	return nil
}

func GetCookie(response *http.Response, key string) string {
	cookie := response.Header.Get("set-cookie")
	if !strings.HasPrefix(cookie, key+"=") {
		return ""
	}

	cookie = strings.TrimPrefix(cookie, key+"=")
	cos := strings.Split(cookie, "; ")
	if len(cos) > 0 {
		return cos[0]
	}

	return ""
}
