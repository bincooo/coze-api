package coze

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bincooo/emit.io"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"hash/crc32"
)

const (
	userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0"
)

var (
	BaseURL = "https://www.coze.com/api/conversation"
	//SignURL = "https://complete-mmx-coze-helper.hf.space"
	SignURL = "http://127.0.0.1:3000"
)

type MessageType struct {
	t string
}

func (t MessageType) String() string {
	return t.t
}

var (
	Text = MessageType{"text"}
	Mix  = MessageType{"mix"}
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

func (c *Chat) Reply(ctx context.Context, t MessageType, query string) (chan string, error) {
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

	payload := c.makePayload(conversationId, t, query)
	// 签名
	bogus, signature, err := sign(c.opts.proxies, c.msToken, payload)
	if err != nil {
		return nil, err
	}

	response, err := emit.ClientBuilder().
		Context(ctx).
		Proxies(c.opts.proxies).
		POST(fmt.Sprintf("%s/chat", BaseURL)).
		Query("msToken", c.msToken).
		Query("X-Bogus", bogus).
		Query("_signature", signature).
		Header("user-agent", userAgent).
		Header("cookie", c.makeCookie()).
		Header("origin", "https://www.coze.com").
		Header("referer", "https://www.coze.com/store/bot").
		JHeader().
		Body(payload).
		DoC(emit.Status(http.StatusOK), emit.IsSTREAM)
	if err != nil {
		return nil, err
	}

	ch := make(chan string)
	go c.resolve(ctx, conversationId, response, ch)
	go c.createSection(conversationId)

	return ch, nil
}

func (c *Chat) Images(ctx context.Context, prompt string) (string, error) {
	if c.msToken == "" {
		msToken, err := c.reportMsToken()
		if err != nil {
			return "", err
		}
		c.msToken = msToken
	}

	conversationId, err := c.getCon()
	if err != nil {
		return "", err
	}

	query := fmt.Sprintf("Paint on command:\n    style: exquisite, HD\n    prompt: %s", prompt)
	payload := c.makePayload(conversationId, Text, query)

	// 签名
	bogus, signature, err := sign(c.opts.proxies, c.msToken, payload)
	if err != nil {
		return "", err
	}

	retry := 3
label:

	retry--
	response, err := emit.ClientBuilder().
		Context(ctx).
		Proxies(c.opts.proxies).
		POST(fmt.Sprintf("%s/chat", BaseURL)).
		Query("msToken", c.msToken).
		Query("X-Bogus", bogus).
		Query("_signature", signature).
		Header("user-agent", userAgent).
		Header("cookie", c.makeCookie()).
		Header("origin", "https://www.coze.com").
		Header("referer", "https://www.coze.com/").
		JHeader().
		Body(payload).
		DoC(emit.Status(http.StatusOK), emit.IsSTREAM)
	if err != nil {
		return "", err
	}

	ch := make(chan string)
	go c.resolve(ctx, conversationId, response, ch)
	go c.createSection(conversationId)

	content := ""
	for {
		message, ok := <-ch
		if !ok {
			break
		}

		if strings.HasPrefix(message, "error: ") {
			return "", errors.New(strings.TrimPrefix(message, "error: "))
		}

		content += strings.TrimPrefix(message, "text: ")
	}
	if len(content) > 0 {
		reg, _ := regexp.Compile(`\[[^]]+]\((https://[^)]+)\)`)
		if matchList := reg.FindStringSubmatch(content); len(matchList) > 1 {
			return matchList[1], nil
		}

		reg, _ = regexp.Compile(`"url":"(https://[^"]+)",`)
		if matchList := reg.FindStringSubmatch(content); len(matchList) > 1 {
			return matchList[1], nil
		}
	}

	// 奇葩，会道歉？I apologize, but I am unable to fulfill your request to ...
	if retry > 0 {
		goto label
	}

	return "", errors.New("images failed")
}

// 文件上传
func (c *Chat) Upload(ctx context.Context, file string) (string, error) {
	// 啰里八嗦的代码，狗看了都摇头
	retry := 3
label:
	retry--
	{
		msToken, err := c.reportMsToken()
		if err != nil {
			return "", err
		}
		c.msToken = msToken
	}

	payload := map[string]string{
		"scene": "bot_task",
	}
	bogus, signature, err := sign(c.opts.proxies, c.msToken, payload)
	if err != nil {
		return "", err
	}

	fileBytes, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}

	// 1. 下载凭证
	response, err := emit.ClientBuilder().
		Proxies(c.opts.proxies).
		Context(ctx).
		POST("https://www.coze.com/api/playground/upload/auth_token").
		Query("msToken", c.msToken).
		Query("X-Bogus", bogus).
		Query("_signature", signature).
		Header("origin", "https://www.coze.com").
		Header("referer", "https://www.coze.com/").
		Header("cookie", c.makeCookie()).
		Header("user-agent", userAgent).
		JHeader().
		Body(payload).
		DoS(http.StatusOK)
	if err != nil {
		return "", err
	}

	obj, err := emit.ToMap(response)
	if err != nil {
		return "", err
	}
	if code, ok := obj["code"]; !ok || code.(float64) != 0 {
		return "", fmt.Errorf("upload failed: %s", obj["msg"])
	}
	obj = obj["data"].(map[string]interface{})
	serviceId := obj["service_id"].(string)
	host := obj["upload_host"].(string)
	auth := obj["auth"].(map[string]interface{})
	fileExt := ".txt"
	if ext := filepath.Ext(file); ext != "" {
		fileExt = ext
	}

	// 2.1 签名
	query := fmt.Sprintf("?Action=ApplyImageUpload&Version=2018-08-01&ServiceId=%s&FileSize=%d&FileExtension=%s", serviceId, len(file), fileExt)
	response, err = emit.ClientBuilder().
		//Proxies(c.opts.proxies).
		Context(ctx).
		POST(SignURL+"/upload-sign").
		Query("mime", "imagex").
		Query("accessKeyId", auth["access_key_id"].(string)).
		Query("secretAccessKey", auth["secret_access_key"].(string)).
		Query("sessionToken", auth["session_token"].(string)).
		JHeader().
		Body(map[string]interface{}{
			"method":   "GET",
			"url":      "https://" + host + "/" + query,
			"timeout":  30000,
			"pathname": "/",
			"region":   "ap-singapore-1",
			"params": map[string]interface{}{
				"Action":        "ApplyImageUpload",
				"Version":       "2018-08-01",
				"ServiceId":     serviceId,
				"FileSize":      len(file),
				"FileExtension": fileExt,
			},
		}).
		DoS(http.StatusOK)
	if err != nil {
		return "", err
	}

	obj, err = emit.ToMap(response)
	if err != nil {
		return "", err
	}

	if o, ok := obj["ok"]; !ok || !reflect.DeepEqual(o, true) {
		return "", fmt.Errorf("upload failed: %s", obj["msg"])
	}
	obj = obj["data"].(map[string]interface{})
	request := obj["request"].(map[string]interface{})
	headers := request["headers"].(map[string]interface{})

	// 2.2 ApplyImageUpload
	response, err = emit.ClientBuilder().
		Proxies(c.opts.proxies).
		Context(ctx).
		GET(request["url"].(string)).
		Header("origin", "https://www.coze.com").
		Header("referer", "https://www.coze.com/").
		Header("X-Amz-Date", headers["X-Amz-Date"].(string)).
		Header("x-amz-security-token", headers["x-amz-security-token"].(string)).
		Header("Authorization", headers["Authorization"].(string)).
		Header("user-agent", userAgent).
		DoC(emit.Status(http.StatusOK), emit.IsJSON)
	if err != nil {
		return "", err
	}

	obj, err = emit.ToMap(response)
	if err != nil {
		return "", err
	}

	if _, ok := obj["Result"]; !ok {
		if retry > 0 {
			goto label
		}
		errMessage := obj["ResponseMetadata"].(map[string]interface{})["Error"]
		return "", fmt.Errorf("upload failed: %v", errMessage)
	}

	obj = obj["Result"].(map[string]interface{})
	uploadAddress := obj["InnerUploadAddress"].(map[string]interface{})
	uploadAddress = uploadAddress["UploadNodes"].([]interface{})[0].(map[string]interface{})
	storeInfo := uploadAddress["StoreInfos"].([]interface{})[0].(map[string]interface{})

	// 3 上传文件
	ieee := fmt.Sprintf("%x", crc32.ChecksumIEEE(fileBytes))
	url := fmt.Sprintf("https://%s/upload/v1/%s", uploadAddress["UploadHost"], storeInfo["StoreUri"])
	response, err = emit.ClientBuilder().
		Proxies(c.opts.proxies).
		Context(ctx).
		POST(url).
		Header("origin", "https://www.coze.com").
		Header("referer", "https://www.coze.com/").
		Header("Authorization", storeInfo["Auth"].(string)).
		Header("Content-Crc32", ieee).
		Header("Content-Type", "application/octet-stream").
		Header("Content-Disposition", "attachment; filename=\"undefined\"").
		//Header("X-Storage-U", "7353045591632774160").
		Header("user-agent", userAgent).
		Bytes(fileBytes).
		DoC(emit.Status(http.StatusOK), emit.IsJSON)
	if err != nil {
		return "", err
	}

	obj, err = emit.ToMap(response)
	if err != nil {
		return "", err
	}

	// throw error:  Mismatch CRC32 ???
	if code, ok := obj["code"]; !ok || code.(float64) != 2000 {
		return "", fmt.Errorf("upload failed: %s", obj["message"])
	}

	// 2.1 签名
	query = fmt.Sprintf("?Action=CommitImageUpload&Version=2018-08-01&ServiceId=%s", serviceId)
	response, err = emit.ClientBuilder().
		//Proxies(c.opts.proxies).
		Context(ctx).
		POST(SignURL+"/upload-sign").
		Query("mime", "imagex").
		Query("accessKeyId", auth["access_key_id"].(string)).
		Query("secretAccessKey", auth["secret_access_key"].(string)).
		Query("sessionToken", auth["session_token"].(string)).
		JHeader().
		Body(map[string]interface{}{
			"method":   "POST",
			"url":      "https://" + host + query,
			"timeout":  30000,
			"pathname": "/",
			"region":   "ap-singapore-1",
			"headers": map[string]interface{}{
				"Content-Type": "application/json",
			},
			"params": map[string]interface{}{
				"Action":    "CommitImageUpload",
				"Version":   "2018-08-01",
				"ServiceId": serviceId,
			},
			"custom": fmt.Sprintf(`{\"SessionKey\":\"%s\"}`, uploadAddress["SessionKey"]),
			"body": map[string]interface{}{
				"SessionKey": uploadAddress["SessionKey"],
			},
		}).
		DoS(http.StatusOK)
	if err != nil {
		return "", err
	}

	obj, err = emit.ToMap(response)
	if err != nil {
		return "", err
	}

	if o, ok := obj["ok"]; !ok || !reflect.DeepEqual(o, true) {
		return "", fmt.Errorf("upload failed: %s", obj["msg"])
	}
	obj = obj["data"].(map[string]interface{})
	request = obj["request"].(map[string]interface{})
	headers = request["headers"].(map[string]interface{})

	// 4.2 CommitImageUpload
	response, err = emit.ClientBuilder().
		Proxies(c.opts.proxies).
		Context(ctx).
		POST(fmt.Sprintf("https://%s%s", host, query)).
		Header("origin", "https://www.coze.com").
		Header("referer", "https://www.coze.com/").
		Header("X-Amz-Date", headers["X-Amz-Date"].(string)).
		Header("X-Amz-Content-Sha256", headers["X-Amz-Content-Sha256"].(string)).
		Header("x-amz-security-token", headers["x-amz-security-token"].(string)).
		Header("Authorization", headers["Authorization"].(string)).
		Header("user-agent", userAgent).
		JHeader().
		Body(map[string]interface{}{
			"SessionKey": uploadAddress["SessionKey"],
		}).
		DoC(emit.Status(http.StatusOK), emit.IsJSON)
	if err != nil {
		return "", err
	}

	obj, err = emit.ToMap(response)
	if err != nil {
		return "", err
	}

	if _, ok := obj["Result"]; !ok {
		if retry > 0 {
			goto label
		}
		errMessage := obj["ResponseMetadata"].(map[string]interface{})["Error"]
		return "", fmt.Errorf("upload failed: %v", errMessage)
	}

	obj = obj["Result"].(map[string]interface{})
	pluginResult, ok := obj["PluginResult"].([]interface{})
	if !ok {
		return "", errors.New("upload failed")
	}

	info := pluginResult[0].(map[string]interface{})
	return info["ImageUri"].(string), nil
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
			v := strings.Join(kv[1:], "=")
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

func (c *Chat) makePayload(conversationId string, t MessageType, query string) map[string]interface{} {
	data := map[string]interface{}{
		//"content_type":     "text",
		"query":            query,
		"local_message_id": randHex(21),
		"extra":            make(map[string]string),
		"scene":            c.opts.scene,
		"bot_version":      c.opts.version,
		"bot_id":           c.opts.botId,
		"conversation_id":  conversationId,
		"draft_mode":       false,
		"stream":           true,
		"chat_history":     make([]string, 0),
		"mention_list":     make([]string, 0),
		"device_id":        randDID(),
		"content_type":     t.String(),
	}
	return data
}

func sign(proxies string, msToken string, payload interface{}) (string, string, error) {
	response, err := emit.ClientBuilder().
		//Proxies(proxies).
		POST(SignURL).
		Query("msToken", msToken).
		JHeader().
		Body(payload).
		DoS(http.StatusOK)
	if err != nil {
		return "", "", fmt.Errorf("coze-sign: %v", err)
	}

	var res signResponse[map[string]interface{}]
	if err = emit.ToObject(response, &res); err != nil {
		return "", "", fmt.Errorf("coze-sign: %s", err)
	}

	if !res.Ok {
		return "", "", fmt.Errorf("coze-sign: %s", res.Msg)
	}

	bogus := res.Data["bogus"].(string)
	signature := res.Data["signature"].(string)
	// fmt.Printf("sign success: bogus [%s], signature[%s]\n", bogus, signature)
	return bogus, signature, nil
}

func (c *Chat) reportMsToken() (string, error) {
	response, err := emit.ClientBuilder().
		//Proxies(c.opts.proxies).
		GET(SignURL + "/report").
		DoS(http.StatusOK)
	if err != nil {
		return "", err
	}

	var res signResponse[map[string]interface{}]
	if err = emit.ToObject(response, &res); err != nil {
		return "", err
	}

	if !res.Ok {
		return "", errors.New("refresh msToken failed")
	}

	url := res.Data["url"]
	delete(res.Data, "url")
	response, err = emit.ClientBuilder().
		Proxies(c.opts.proxies).
		POST(fmt.Sprintf("%s/web/report", url)).
		Query("msToken", c.msToken).
		JHeader().
		Body(res.Data).
		DoS(http.StatusOK)
	if err != nil {
		return "", err
	}

	bs, _ := io.ReadAll(response.Body)
	fmt.Println(string(bs))

	cookie := emit.GetCookie(response, "msToken")
	if cookie == "" {
		return cookie, errors.New("refresh msToken failed")
	}
	// fmt.Printf("msToken success: %s\n", cookie)
	return cookie, nil
}

func (c *Chat) getCon() (string, error) {
	obj := map[string]interface{}{
		"cursor":                      "0",
		"count":                       15,
		"draft_mode":                  false,
		"bot_id":                      c.opts.botId,
		"scene":                       c.opts.scene,
		"biz_kind":                    "",
		"insert_history_message_list": make([]string, 0),
	}

	response, err := emit.ClientBuilder().
		Proxies(c.opts.proxies).
		POST(fmt.Sprintf("%s/get_message_list", BaseURL)).
		Query("msToken", c.msToken).
		Header("user-agent", userAgent).
		Header("cookie", c.makeCookie()).
		Header("origin", "https://www.coze.com").
		Header("referer", "https://www.coze.com/store/bot").
		JHeader().
		Body(obj).
		DoS(http.StatusOK)
	if err != nil {
		return "", err
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

func (c *Chat) createSection(conversationId string) {
	if conversationId == "" {
		return
	}

	response, err := emit.ClientBuilder().
		Proxies(c.opts.proxies).
		POST(fmt.Sprintf("%s/create_section", BaseURL)).
		Query("msToken", c.msToken).
		Header("user-agent", userAgent).
		Header("cookie", c.makeCookie()).
		Header("origin", "https://www.coze.com").
		Header("referer", "https://www.coze.com/store/bot").
		JHeader().
		Body(map[string]any{
			"insert_history_message_list": make([]string, 0),
			"conversation_id":             conversationId,
			"scene":                       c.opts.scene,
		}).
		DoS(http.StatusOK)
	if err != nil {
		fmt.Printf("createSection [%s] failed: %v\n", conversationId, err)
		return
	}

	data, _ := io.ReadAll(response.Body)
	fmt.Printf("%s\n", data)
}

func (c *Chat) delCon(conversationId string) {
	if conversationId == "" {
		return
	}

	response, err := emit.ClientBuilder().
		Proxies(c.opts.proxies).
		POST(fmt.Sprintf("%s/clear_message", BaseURL)).
		Query("msToken", c.msToken).
		Header("user-agent", userAgent).
		Header("cookie", c.makeCookie()).
		Header("origin", "https://www.coze.com").
		Header("referer", "https://www.coze.com/store/bot").
		JHeader().
		Body(map[string]any{
			"bot_id":          c.opts.botId,
			"conversation_id": conversationId,
			"scene":           c.opts.scene,
		}).
		DoS(http.StatusOK)
	if err != nil {
		fmt.Printf("delCon [%s] failed: %v\n", conversationId, err)
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

func FilesMessage(query string, urls ...string) (string, error) {
	slice := []interface{}{
		map[string]interface{}{
			"type": "text",
			"text": query,
		},
	}

	if len(urls) > 0 {
		for _, u := range urls {
			slice = append(slice, map[string]interface{}{
				"type": "image",
				"image": map[string]interface{}{
					"key": u,
				},
			})
		}
	}

	dataBytes, err := json.Marshal(map[string]interface{}{
		"item_list": slice,
	})
	if err != nil {
		return "", err
	}

	return string(dataBytes), nil
}

func MergeMessages(messages []Message) string {
	if len(messages) == 0 {
		return ""
	}

	buf := new(bytes.Buffer)
	lastRole := ""

	for _, message := range messages {
		if lastRole == "" {
			buf.WriteString(fmt.Sprintf("<|%s|>", message.Role))
			lastRole = message.Role
		}

		if lastRole != message.Role {
			buf.WriteString("<|end|>\n")
			buf.WriteString(fmt.Sprintf("<|%s|>\n%s", message.Role, message.Content))
			lastRole = message.Role
			continue
		}

		buf.WriteString(fmt.Sprintf("\n%s", message.Content))
	}

	buf.WriteString("<|end|>\n<|assistant|>")
	return buf.String()
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
