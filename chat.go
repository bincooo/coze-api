package coze

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/net/proxy"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
)

const (
	baseURL   = "https://www.coze.com/api/conversation"
	signUrl   = "https://complete-mmx-coze-helper.hf.space"
	sysPrompt = "You will play as a gpt-4 with a 128k token, and the following text is information about your historical conversations with the user:"
	tabs      = "\n    "
	userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0"
)

func NewDefaultOptions(botId, version string, scene int, proxies string) Options {
	return Options{
		botId:   botId,
		version: version,
		scene:   scene,
		proxies: proxies,
	}
}

func New(cookie, msToken string, opts Options) Chat {
	return Chat{
		cookie:  cookie,
		msToken: msToken,
		opts:    opts,
	}
}

func (c Chat) Reply(ctx context.Context, messages []Message) (chan string, error) {
	query := mergeMessages(messages)

	conversationId, err := c.getCon()
	if err != nil {
		return nil, err
	}

	data := map[string]any{
		"bot_id":                      c.opts.botId,
		"conversation_id":             conversationId,
		"content_type":                "text",
		"query":                       query,
		"scene":                       c.opts.scene,
		"local_message_id":            randHex(21),
		"extra":                       make(map[string]string),
		"bot_version":                 c.opts.version,
		"stream":                      true,
		"chat_history":                make([]int, 0),
		"insert_history_message_list": make([]int, 0),
	}

	marshal, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	// 签名
	bogus, signature, err := sign(c.opts.proxies, c.msToken, marshal)
	if err != nil {
		return nil, err
	}

	response, err := fetch(c.opts.proxies, "chat", c.cookie, fmt.Sprintf("%s&X-Bogus=%s&_signature=%s", c.msToken, bogus, signature), marshal)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, errors.New(response.Status)
	}

	ch := make(chan string)
	go resolve(ctx, response, ch)
	return ch, nil
}

func (c Chat) Images(ctx context.Context, prompt string) (string, error) {
	conversationId, err := c.getCon()
	if err != nil {
		return "", err
	}

	query := fmt.Sprintf("Paint on command:\n    style: exquisite, HD\n    prompt: %s", prompt)
	data := map[string]any{
		"bot_id":                      c.opts.botId,
		"conversation_id":             conversationId,
		"content_type":                "text",
		"query":                       query,
		"scene":                       c.opts.scene,
		"local_message_id":            randHex(21),
		"extra":                       make(map[string]string),
		"bot_version":                 c.opts.version,
		"stream":                      true,
		"chat_history":                make([]int, 0),
		"insert_history_message_list": make([]int, 0),
	}

	marshal, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	// 签名
	bogus, signature, err := sign(c.opts.proxies, c.msToken, marshal)
	if err != nil {
		return "", err
	}

	response, err := fetch(c.opts.proxies, "chat", c.cookie, fmt.Sprintf("%s&X-Bogus=%s&_signature=%s", c.msToken, bogus, signature), marshal)
	if err != nil {
		return "", err
	}

	if response.StatusCode != http.StatusOK {
		return "", errors.New(response.Status)
	}

	ch := make(chan string)
	go resolve(ctx, response, ch)

	for {
		message, ok := <-ch
		if !ok {
			return "", errors.New("paint failed")
		}

		if strings.HasPrefix(message, "error: ") {
			return "", errors.New(strings.TrimPrefix(message, "error: "))
		}

		reg, _ := regexp.Compile(`!\[[^]]+]\((https://[^)]+)\)`)
		if matchList := reg.FindStringSubmatch(message); len(matchList) > 1 {
			return matchList[1], nil
		}
	}
}

func sign(proxies string, msToken string, marshal []byte) (string, string, error) {
	response, err := fetch(proxies, signUrl, "", msToken, marshal)
	if err != nil {
		return "", "", err
	}
	if response.StatusCode != http.StatusOK {
		return "", "", errors.New(response.Status)
	}

	data, err := io.ReadAll(response.Body)
	if err != nil {
		return "", "", err
	}

	var dict map[string]interface{}
	if err = json.Unmarshal(data, &dict); err != nil {
		return "", "", err
	}

	if !reflect.DeepEqual(dict["ok"], true) {
		return "", "", errors.New(string(data))
	}

	kv, ok := dict["data"].(map[string]interface{})
	if !ok {
		return "", "", errors.New(string(data))
	}

	return kv["bogus"].(string), kv["signature"].(string), nil
}

func (c Chat) getCon() (string, error) {
	obj := map[string]any{
		"bot_id": c.opts.botId,
		"scene":  c.opts.scene,
	}

	marshal, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}

	response, err := fetch(c.opts.proxies, "get_conversation", c.cookie, c.msToken, marshal)
	if err != nil {
		return "", err
	}

	if response.StatusCode != http.StatusOK {
		return "", errors.New(response.Status)
	}

	var dict map[string]interface{}
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	err = json.Unmarshal(data, &dict)
	if err != nil {
		return "", err
	}

	if code, ok := dict["code"].(float64); ok && code == 0 {
		return dict["conversation_id"].(string), nil
	}

	return "", fmt.Errorf("%s", data)
}

func resolve(ctx context.Context, response *http.Response, ch chan string) {
	var data []byte
	before := []byte("data:")
	errorBefore := []byte("{\"code\":")
	defer close(ch)

	r := bufio.NewReader(response.Body)
	// 继续执行返回false
	Do := func() bool {
		line, prefix, err := r.ReadLine()
		if err != nil {
			if err != io.EOF {
				ch <- fmt.Sprintf("error: %v", err)
			}
			return true
		}

		data = append(data, line...)
		if prefix {
			return false
		}

		if bytes.HasPrefix(data, errorBefore) {
			ch <- fmt.Sprintf("error: %s", data)
			return true
		}

		if bytes.HasPrefix(data, before) {
			var msg resMessage
			data = bytes.TrimPrefix(data, before)
			if len(data) == 0 {
				data = nil
				return false
			}

			err = json.Unmarshal(data, &msg)
			if err != nil {
				ch <- fmt.Sprintf("error: %v", err)
				return true
			}

			if msg.Message.Role == "assistant" {
				if msg.Message.Type == "answer" {
					if strings.Contains(msg.Message.Content, "limit on the number of messages") {
						ch <- fmt.Sprintf("error: %v", msg.Message.Content)
						return true
					}
					ch <- fmt.Sprintf("text: %s", msg.Message.Content)
				}
				if msg.Message.Type == "tool_response" && strings.HasPrefix(msg.Message.Content, "Failed:") {
					ch <- fmt.Sprintf("error: %v", msg.Message.Content)
					return true
				}
			}
		}

		data = nil
		return false
	}

	for {
		select {
		case <-ctx.Done():
			ch <- fmt.Sprintf("error: context done")
		default:
			if stop := Do(); stop {
				return
			}
		}
	}
}

func mergeMessages(messages []Message) string {
	if len(messages) == 0 {
		return ""
	}

	buf := ""
	lastRole := ""

	for _, message := range messages {
		if lastRole == "" || lastRole != message.Role {
			lastRole = message.Role
			buf += fmt.Sprintf("\n%s: %s%s", message.Role, tabs, strings.Join(strings.Split(message.Content, "\n"), tabs))
			continue
		}
		buf += fmt.Sprintf("\n%s%s", tabs, strings.Join(strings.Split(message.Content, "\n"), tabs))
	}

	join := strings.Join(strings.Split(buf, "\n"), tabs)
	return fmt.Sprintf(
		"%s [%s%s\n\n]\nThe above uses [\"user:\", \"assistant:\", \"system\", \"function\"] as text symbols for paragraph segmentation.",
		sysPrompt, tabs, join)
}

func fetch(proxies, route, cookie, msToken string, body []byte) (*http.Response, error) {
	if !strings.HasPrefix(route, "http") {
		route = baseURL + "/" + route
	} else {
		if strings.Contains(route, "127.0.0.1") || strings.Contains(route, "localhost") {
			proxies = ""
		}
	}

	client, err := newClient(proxies)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s?msToken=%s", route, msToken), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	h := request.Header
	h.Add("content-type", "application/json")
	h.Add("cookie", "sessionid="+cookie)
	h.Add("userAgent", userAgent)
	h.Add("origin", "https://www.coze.com")
	h.Add("referer", "https://www.coze.com/store/bot")

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func randHex(num int) string {
	bin := "1234567890abcdefghijklmnopqrstuvwxyz"
	binL := len(bin)

	var buf []byte
	for x := 0; x < num; x++ {
		buf = append(buf, bin[rand.Intn(binL-1)])
	}
	return string(buf)
}

func newClient(proxies string) (*http.Client, error) {
	client := http.DefaultClient
	if proxies != "" {
		proxiesUrl, err := url.Parse(proxies)
		if err != nil {
			return nil, err
		}

		if proxiesUrl.Scheme == "http" || proxiesUrl.Scheme == "https" {
			client = &http.Client{
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
			client = &http.Client{
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

	return client, nil
}
