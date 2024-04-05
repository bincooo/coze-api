package coze

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bincooo/coze-api/common"
	"io"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	sys       = "[Start New Conversation]\nYou will be playing the role of a GPT-4 model with a 128k token limit, and the following text is information about your historical conversations with the user:"
	tabs      = "\n    "
	userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0"
)

var (
	BaseURL = "https://www.coze.com/api/conversation"
	SignURL = "https://complete-mmx-coze-helper.hf.space"
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

func (c *Chat) Reply(ctx context.Context, query string) (chan string, error) {
	if c.msToken == "" {
		msToken, err := c.reportMsToken()
		if err != nil {
			return nil, err
		}
		c.msToken = msToken
	}

	conversationId, err := c.getCon()
	if err != nil {
		return nil, err
	}

	payload := c.makePayload(conversationId, query)
	// 签名
	bogus, signature, err := sign(c.opts.proxies, c.msToken, payload)
	if err != nil {
		return nil, err
	}

	response, err := common.New().
		Context(ctx).
		Proxies(c.opts.proxies).
		Method(http.MethodPost).
		URL(fmt.Sprintf("%s/chat", BaseURL)).
		Query("msToken", c.msToken).
		Query("X-Bogus", bogus).
		Query("_signature", signature).
		Header("user-agent", userAgent).
		Header("cookie", c.makeCookie()).
		Header("origin", "https://www.coze.com").
		Header("referer", "https://www.coze.com/store/bot").
		JsonHeader().
		SetBody(payload).
		Do()
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, errors.New(response.Status)
	}

	ch := make(chan string)
	go c.resolve(ctx, conversationId, response, ch)
	return ch, nil
}

func (c *Chat) Images(ctx context.Context, prompt string) (string, error) {
	conversationId, err := c.getCon()
	if err != nil {
		return "", err
	}

	query := fmt.Sprintf("Paint on command:\n    style: exquisite, HD\n    prompt: %s", prompt)
	payload := c.makePayload(conversationId, query)

	// 签名
	bogus, signature, err := sign(c.opts.proxies, c.msToken, payload)
	if err != nil {
		return "", err
	}

	response, err := common.New().
		Context(ctx).
		Proxies(c.opts.proxies).
		Method(http.MethodPost).
		URL(fmt.Sprintf("%s/chat", BaseURL)).
		Query("msToken", c.msToken).
		Query("X-Bogus", bogus).
		Query("_signature", signature).
		Header("user-agent", userAgent).
		Header("cookie", c.makeCookie()).
		Header("origin", "https://www.coze.com").
		Header("referer", "https://www.coze.com/store/bot").
		JsonHeader().
		SetBody(payload).
		Do()
	if err != nil {
		return "", err
	}

	if response.StatusCode != http.StatusOK {
		return "", errors.New(response.Status)
	}

	ch := make(chan string)
	go c.resolve(ctx, conversationId, response, ch)

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

func (c *Chat) makeCookie() (cookie string) {
	var cookies []string
	hmt := false

	if !strings.Contains(c.cookie, "sessionid") {
		cookies = strings.Split("sessionid="+c.cookie, "; ")
	} else {
		cookies = strings.Split(c.cookie, "; ")
	}

	for _, co := range cookies {
		kv := strings.Split(co, "=")
		if len(kv) > 1 {
			k := kv[0]
			v := strings.Join(kv[1:], "")
			if k == "msToken" {
				v = c.msToken
				hmt = true
			}
			cookie += fmt.Sprintf("%s=%s; ", k, v)
		}
	}
	if !hmt {
		cookie += fmt.Sprintf("msToken=%s; ", c.msToken)
	}
	return
}

func (c *Chat) makePayload(conversationId string, query string) map[string]interface{} {
	data := map[string]interface{}{
		"bot_id":                      c.opts.botId,
		"conversation_id":             conversationId,
		"content_type":                "text",
		"query":                       query,
		"scene":                       c.opts.scene,
		"local_message_id":            randHex(21),
		"extra":                       make(map[string]string),
		"bot_version":                 c.opts.version,
		"device_id":                   randDID(),
		"draft_mode":                  false,
		"stream":                      true,
		"chat_history":                make([]int, 0),
		"insert_history_message_list": make([]int, 0),
	}
	return data
}

func sign(proxies string, msToken string, payload interface{}) (string, string, error) {
	response, err := common.New().
		Proxies(proxies).
		Method(http.MethodPost).
		URL(SignURL).
		Query("msToken", msToken).
		JsonHeader().
		SetBody(payload).
		Do()
	if err != nil {
		return "", "", fmt.Errorf("coze-sign: %v", err)
	}

	if response.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("coze-sign: %s", response.Status)
	}

	var res signResponse[map[string]interface{}]
	if err = common.ToObj(response, &res); err != nil {
		return "", "", fmt.Errorf("coze-sign: %s", err)
	}

	if !res.Ok {
		return "", "", fmt.Errorf("coze-sign: %s", res.Data)
	}

	bogus := res.Data["bogus"].(string)
	signature := res.Data["signature"].(string)
	// fmt.Printf("sign success: bogus [%s], signature[%s]\n", bogus, signature)
	return bogus, signature, nil
}

func (c *Chat) reportMsToken() (string, error) {
	response, err := common.New().
		Proxies(c.opts.proxies).
		URL(SignURL + "/report").
		Do()
	if err != nil {
		return "", err
	}

	if response.StatusCode != http.StatusOK {
		return "", errors.New(response.Status)
	}

	var res signResponse[map[string]interface{}]
	if err = common.ToObj(response, &res); err != nil {
		return "", err
	}

	if !res.Ok {
		return "", errors.New("refresh msToken failed")
	}

	response, err = common.New().
		Proxies(c.opts.proxies).
		Method(http.MethodPost).
		URL(fmt.Sprintf("%s/web/report", res.Data["url"])).
		Query("msToken", c.msToken).
		JsonHeader().
		SetBody(res.Data).
		Do()
	if err != nil {
		return "", err
	}

	if response.StatusCode != http.StatusOK {
		return "", errors.New(response.Status)
	}

	cookie := common.GetCookie(response, "msToken")
	if cookie == "" {
		return cookie, errors.New("refresh msToken failed")
	}
	// fmt.Printf("msToken success: %s\n", cookie)
	return cookie, nil
}

func (c *Chat) getCon() (string, error) {
	obj := map[string]interface{}{
		"bot_id": c.opts.botId,
		"scene":  c.opts.scene,
	}

	response, err := common.New().
		Proxies(c.opts.proxies).
		Method(http.MethodPost).
		URL(fmt.Sprintf("%s/get_conversation", BaseURL)).
		Query("msToken", c.msToken).
		Header("user-agent", userAgent).
		Header("cookie", c.makeCookie()).
		Header("origin", "https://www.coze.com").
		Header("referer", "https://www.coze.com/store/bot").
		JsonHeader().
		SetBody(obj).
		Do()
	if err != nil {
		return "", err
	}

	if response.StatusCode != http.StatusOK {
		return "", errors.New(response.Status)
	}

	data, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	var dict map[string]interface{}
	err = json.Unmarshal(data, &dict)
	if err != nil {
		return "", err
	}

	if code, ok := dict["code"].(float64); ok && code == 0 {
		return dict["conversation_id"].(string), nil
	}

	return "", fmt.Errorf("%s", data)
}

func (c *Chat) delCon(conversationId string) {
	if conversationId == "" {
		return
	}

	response, err := common.New().
		Proxies(c.opts.proxies).
		Method(http.MethodPost).
		URL(fmt.Sprintf("%s/clear_message", BaseURL)).
		Query("msToken", c.msToken).
		Header("user-agent", userAgent).
		Header("cookie", c.makeCookie()).
		Header("origin", "https://www.coze.com").
		Header("referer", "https://www.coze.com/store/bot").
		JsonHeader().
		SetBody(map[string]any{
			"bot_id":          c.opts.botId,
			"conversation_id": conversationId,
			"scene":           c.opts.scene,
		}).
		Do()
	if err != nil {
		fmt.Printf("delCon [%s] failed: %v\n", conversationId, err)
		return
	}

	if response.StatusCode != http.StatusOK {
		fmt.Printf("delCon [%s] failed: %s\n", conversationId, response.Status)
		return
	}

	data, _ := io.ReadAll(response.Body)
	fmt.Printf("%s\n", data)
}

func (c *Chat) resolve(ctx context.Context, conversationId string, response *http.Response, ch chan string) {
	var data []byte
	before := []byte("data:")
	errorBefore := []byte("{\"code\":")
	defer close(ch)
	defer c.delCon(conversationId)

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
					if IsLimit(msg.Message.Content) {
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
			ch <- "error: context done"
			return
		default:
			if stop := Do(); stop {
				return
			}
		}
	}
}

func IsLimit(content string) bool {
	if strings.Contains(content, "limit on the number of messages") {
		return true
	}
	if strings.Contains(content, "daily limit for sending messages") {
		return true
	}
	return false
}

func MergeMessages(messages []Message) string {
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
	uid := randHex(20)
	end := "The above uses [\"user:\", \"assistant:\", \"system:\", \"function:\"] as text symbols for paragraph segmentation, Please do not output separator prefixes."
	return fmt.Sprintf("%s \n--- Start %s ---%s%s\n\n--- End %s ---\n%s", sys, uid, tabs, join, uid, end)
}

func randDID() string {
	return fmt.Sprintf("%d", int64(rand.Intn(999999999))+time.Now().Unix())
}

func randHex(num int) string {
	bin := "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_"
	binL := len(bin)

	var buf []byte
	for x := 0; x < num; x++ {
		buf = append(buf, bin[rand.Intn(binL-1)])
	}
	return string(buf)
}
