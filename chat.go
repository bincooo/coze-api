package coze

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	baseURL   = "https://www.coze.com/api/conversation"
	sysPrompt = "You will play as a gpt-4 with a 128k token, and the following text is information about your historical conversations with the user:"
	tabs      = "\n    "
)

func NewDefaultOptions(botId string, scene int, proxies string) Options {
	return Options{
		botId:   botId,
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

func (c Chat) Reply(messages []Message) (chan string, error) {
	query := mergeMessages(messages)

	conversationId, err := c.getCon()
	if err != nil {
		return nil, err
	}

	data := map[string]any{
		"bot_id":          c.opts.botId,
		"conversation_id": conversationId,
		"content_type":    "text",
		"query":           query,
		"scene":           c.opts.scene,
		"stream":          true,
	}

	marshal, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	response, err := fetch(c.opts.proxies, "chat", c.cookie, c.msToken, marshal)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, errors.New(response.Status)
	}

	ch := make(chan string)
	go resolve(response, ch)
	return ch, nil
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

func resolve(response *http.Response, ch chan string) {
	var data []byte
	before := []byte("data:")
	defer close(ch)

	r := bufio.NewReader(response.Body)
	for {
		line, prefix, err := r.ReadLine()
		if err != nil {
			if err != io.EOF {
				ch <- fmt.Sprintf("error: %v", err)
			}
			return
		}

		data = append(data, line...)
		if prefix {
			continue
		}

		if bytes.HasPrefix(data, before) {
			var msg resMessage
			data = bytes.TrimPrefix(data, before)
			if len(data) == 0 {
				data = nil
				continue
			}

			err = json.Unmarshal(data, &msg)
			if err != nil {
				ch <- fmt.Sprintf("error: %v", err)
				return
			}

			if msg.Message.Role == "assistant" && msg.Message.Type == "answer" {
				ch <- fmt.Sprintf("text: %s", msg.Message.Content)
			}
		}

		data = nil
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
			buf += fmt.Sprintf("%s: %s%s", message.Role, tabs, strings.Join(strings.Split(message.Content, "\n"), tabs))
			continue
		}
		buf += fmt.Sprintf("\n%s%s", tabs, strings.Join(strings.Split(message.Content, "\n"), tabs))
	}

	join := strings.Join(strings.Split(buf, "\n"), tabs)
	return fmt.Sprintf(
		"%s [%s%s\n]\nThe above uses [\"user:\", \"assistant:\", \"system\", \"function\"] as text symbols for paragraph segmentation.",
		sysPrompt, tabs, join)
}

func fetch(proxies, route, cookie, msToken string, body []byte) (*http.Response, error) {
	client := http.DefaultClient
	if proxies != "" {
		client = &http.Client{
			Transport: &http.Transport{
				Proxy: func(req *http.Request) (*url.URL, error) {
					return url.Parse(proxies)
				},
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
	}

	request, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/%s?msToken=%s", baseURL, route, msToken), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	h := request.Header
	h.Add("Content-Type", "application/json")
	h.Add("Cookie", "sessionid="+cookie)

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	return response, nil
}
