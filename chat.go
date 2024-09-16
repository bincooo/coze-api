package coze

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bincooo/emit.io"
	"github.com/sirupsen/logrus"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"hash/crc32"
)

const (
	userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0"
)

var (
	BaseURL = "https://www.coze.com/api/conversation"
	SignURL = "https://chat-completion-helper.hf.space"
	//SignURL = "http://127.0.0.1:3000"

	ModelGpt4o_8k            = "gpt4o-8k"
	ModelGpt4o_32k           = "gpt4o-32k"
	ModelGpt4o_128k          = "gpt4o-128k"
	ModelGpt4_125k           = "gpt4-125k"
	ModelGpt35_16k           = "gpt35-16k"
	ModelClaude35Sonnet_200k = "claude-35-sonnet-200k"
	ModelClaude3Haiku_200k   = "claude-35-haiku-200k"

	modelMap = map[string]string{
		ModelGpt4o_8k:   "124",
		ModelGpt4o_32k:  "1719845284",
		ModelGpt4o_128k: "1716293913",
		ModelGpt4_125k:  "133",
		ModelGpt35_16k:  "113",

		ModelClaude35Sonnet_200k: "1717261861",
		ModelClaude3Haiku_200k:   "1720702293",
	}
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

func ModelToId(model string) string {
	return modelMap[model]
}

func NewDefaultOptions(botId, version string, scene int, owner bool, proxies string) Options {
	return Options{
		BotId:   botId,
		version: version,
		scene:   scene,
		proxies: proxies,
		owner:   owner,
	}
}

func (opts *Options) Bot(id, version string, scene int, o bool) {
	opts.BotId = id
	opts.version = version
	opts.scene = scene
	opts.owner = o
}

func New(cookie, msToken string, opts Options) Chat {
	return Chat{
		cookie:  cookie,
		msToken: msToken,
		opts:    opts,
	}
}

func (c *Chat) Ja3(ja3 string) {
	c.ja3 = ja3
}

func (c *Chat) Bot(id, version string, scene int, o bool) {
	c.opts.Bot(id, version, scene, o)
}

func (c *Chat) Reply(ctx context.Context, t MessageType, query string) (chan string, error) {
	if c.webSdk {
		return c.replyWebSdk(ctx, t, c.messages, query)
	}

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
	bogus, signature, err := c.sign("", payload)
	if err != nil {
		return nil, err
	}

	response, err := emit.ClientBuilder(c.session).
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
		if emit.IsJSON(response) == nil {
			err = errors.New(emit.TextResponse(response))
		}
		return nil, err
	}

	ch := make(chan string)
	go c.resolve(ctx, conversationId, response, ch)
	go c.createSection(conversationId)

	return ch, nil
}

func (c *Chat) replyWebSdk(ctx context.Context, t MessageType, histories []interface{}, query string) (chan string, error) {
	if c.msToken == "" {
		msToken, err := c.reportMsToken()
		if err != nil {
			return nil, err
		}
		c.msToken = msToken
	}

	payload, err := c.makeWebSdkPayload(ctx, t, histories, query)
	if err != nil {
		return nil, err
	}
	// 签名
	bogus, signature, err := c.sign("api.coze.com/open_api/v1/web_chat", payload)
	if err != nil {
		return nil, err
	}

	response, err := emit.ClientBuilder(c.session).
		Context(ctx).
		Proxies(c.opts.proxies).
		Ja3(c.ja3).
		POST("https://api.coze.com/open_api/v1/web_chat").
		Query("msToken", c.msToken).
		Query("X-Bogus", bogus).
		Query("_signature", signature).
		Header("user-agent", userAgent).
		Header("cookie", "msToken="+c.msToken).
		Header("origin", "https://api.coze.com").
		Header("referer", "https://api.coze.com/open-platform/sdk/chatapp/?params="+
			url.QueryEscape(`{"chatClientId":"`+randHex(21)+`","chatConfig":{"bot_id":"`+
				c.opts.BotId+`","user":"`+
				c.user+`","conversation_id":"`+randHex(21)+`"},"componentProps":{"layout":"pc","lang":"en","uploadable":true,"title":"Coze"}}`)).
		JHeader().
		Body(payload).
		DoC(emit.Status(http.StatusOK), emit.IsSTREAM)
	if err != nil {
		if emit.IsJSON(response) == nil {
			err = errors.New(emit.TextResponse(response))
		}
		return nil, err
	}

	ch := make(chan string)
	go c.resolve(ctx, "", response, ch)
	return ch, nil
}

// 获取bots
func (c *Chat) QueryBots(ctx context.Context) ([]interface{}, error) {
	if c.msToken == "" {
		msToken, err := c.reportMsToken()
		if err != nil {
			return nil, err
		}
		c.msToken = msToken
	}
	space, err := c.GetSpace(ctx)
	if err != nil {
		return nil, err
	}

	response, err := emit.ClientBuilder(c.session).
		Context(ctx).
		Proxies(c.opts.proxies).
		POST("https://www.coze.com/api/draftbot/get_draft_bot_list").
		Query("msToken", c.msToken).
		Header("user-agent", userAgent).
		Header("cookie", c.makeCookie()).
		Header("origin", "https://www.coze.com").
		Header("referer", "https://www.coze.com/space/"+space+"/bot").
		JHeader().
		Body(map[string]interface{}{
			"space_id":              space,
			"order_by":              1,
			"team_bot_type":         0,
			"page_index":            1,
			"page_size":             50,
			"is_publish":            0,
			"draft_bot_status_list": []int{1, 2, 3},
		}).
		DoC(emit.Status(http.StatusOK), emit.IsJSON)
	if err != nil {
		return nil, err
	}

	obj, err := emit.ToMap(response)
	if err != nil {
		return nil, err
	}

	if code, ok := obj["code"].(float64); !ok || code != 0 {
		return nil, errors.New("query failed")
	}

	data, ok := obj["data"].(map[string]interface{})
	if !ok {
		return nil, errors.New("query failed")
	}

	slice, ok := data["bot_draft_list"].([]interface{})
	if !ok {
		return make([]interface{}, 0), nil
	}
	return slice, nil
}

// 创建bot
func (c *Chat) Create(ctx context.Context, name string) (botId string, err error) {
	if c.msToken == "" {
		msToken, err := c.reportMsToken()
		if err != nil {
			return "", err
		}
		c.msToken = msToken
	}
	space, err := c.GetSpace(ctx)
	if err != nil {
		return "", err
	}

	payload := map[string]interface{}{
		"space_id": space,
		"name":     name,
		"icon_uri": "FileBizType.BIZ_BOT_ICON/default_bot_icon6.png",
		"monetization_conf": map[string]interface{}{
			"is_enable": true,
		},
	}

	response, err := emit.ClientBuilder(c.session).
		Context(ctx).
		Proxies(c.opts.proxies).
		Option(c.connOpts).
		POST("https://www.coze.com/api/draftbot/create").
		Query("msToken", c.msToken).
		Header("user-agent", userAgent).
		Header("cookie", c.makeCookie()).
		Header("origin", "https://www.coze.com").
		Header("referer", "https://www.coze.com/space/"+space+"/bot").
		JHeader().
		Body(payload).
		DoC(emit.Status(http.StatusOK), emit.IsJSON)
	if err != nil {
		return "", err
	}

	obj, err := emit.ToMap(response)
	if err != nil {
		return "", err
	}

	if code, ok := obj["code"].(float64); !ok || code != 0 {
		return "", errors.New("create failed")
	}

	data, ok := obj["data"].(map[string]interface{})
	if !ok {
		return "", errors.New("create failed")
	}

	return data["bot_id"].(string), nil
}

// 发布bot
func (c *Chat) Publish(ctx context.Context, botId string, connectors map[string]interface{}) error {
	if c.msToken == "" {
		msToken, err := c.reportMsToken()
		if err != nil {
			return err
		}
		c.msToken = msToken
	}
	space, err := c.GetSpace(ctx)
	if err != nil {
		return err
	}

	payload := map[string]interface{}{
		"botMode":        0,
		"bot_id":         botId,
		"commit_version": "",
		"connectors":     connectors,
		"history_info":   "",
		"publish_id":     randHex(21),
		"publish_type":   0,
		"space_id":       space,
	}

	response, err := emit.ClientBuilder(c.session).
		Context(ctx).
		Proxies(c.opts.proxies).
		POST("https://www.coze.com/api/draftbot/publish").
		Query("msToken", c.msToken).
		Header("user-agent", userAgent).
		Header("cookie", c.makeCookie()).
		Header("referer", "https://www.coze.com/token").
		JHeader().
		Body(payload).
		DoC(emit.Status(http.StatusOK), emit.IsJSON)
	if err != nil {
		return err
	}

	defer response.Body.Close()
	obj, err := emit.ToMap(response)
	if err != nil {
		return err
	}

	if code, ok := obj["code"].(float64); !ok || code != 0 {
		return errors.New("publish failed: " + obj["msg"].(string))
	}

	return nil
}

// 查询可用额度
func (c *Chat) QueryWebSdkCredits(ctx context.Context) (int, error) {
	curr := time.Now()
	t1 := time.Date(curr.Year(), curr.Month(), 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(curr.Year(), curr.Month(), 1, 0, 0, 0, 0, time.UTC).
		AddDate(0, 1, 0).
		Add(-time.Second)

	if c.msToken == "" {
		msToken, err := c.reportMsToken()
		if err != nil {
			return 0, err
		}
		c.msToken = msToken
	}

	response, err := emit.ClientBuilder(c.session).
		Context(ctx).
		Proxies(c.opts.proxies).
		GET("https://www.coze.com/api/marketplace/trade/get_account_bills").
		Query("account_type", "token").
		Query("start_timestamp_ms", strconv.FormatInt(t1.UnixMilli(), 10)).
		Query("end_timestamp_ms", strconv.FormatInt(t2.UnixMilli(), 10)).
		Query("msToken", c.msToken).
		Header("user-agent", userAgent).
		Header("cookie", c.makeCookie()).
		Header("referer", "https://www.coze.com/token").
		DoC(emit.Status(http.StatusOK), emit.IsJSON)
	if err != nil {
		return 0, err
	}

	obj, err := emit.ToMap(response)
	if err != nil {
		return 0, err
	}

	if code, ok := obj["code"].(float64); !ok || code != 0 {
		marshal, _ := json.Marshal(obj)
		return 0, fmt.Errorf("%s", marshal)
	}

	inter, ok := obj["data"].(interface{})
	if !ok {
		return 0, errors.New("failed to fetch account free balance")
	}

	data, ok := inter.(map[string]interface{})["bill_details"]
	if !ok {
		return 0, errors.New("failed to fetch account free balance")
	}

	billDetails := data.([]interface{})
	if len(billDetails) == 0 {
		return 100, nil
	}

	bill, ok := billDetails[0].(map[string]interface{})
	if !ok {
		return 0, errors.New("failed to fetch account free balance")
	}

	desc := bill["desc"].(string)
	compile := regexp.MustCompile(`\((\d+/100)\)`)
	matched := compile.FindStringSubmatch(desc)
	if len(matched) < 2 {
		return 0, errors.New("failed to fetch account free balance")
	}

	split := strings.Split(matched[1], "/")
	total, _ := strconv.Atoi(split[1])
	used, _ := strconv.Atoi(split[0])
	return total - used, nil
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
	bogus, signature, err := c.sign("", payload)
	if err != nil {
		return "", err
	}

	retry := 3
label:

	retry--
	response, err := emit.ClientBuilder(c.session).
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

func (c *Chat) Session(session *emit.Session) {
	c.session = session
}

func (c *Chat) ConnectOption(connOpts *emit.ConnectOption) {
	c.connOpts = connOpts
}

func (c *Chat) WebSdk(messages []interface{}) *Chat {
	c.webSdk = true
	c.messages = messages
	return c
}

func (c *Chat) BotInfo(ctx context.Context) (value map[string]interface{}, err error) {
	retry := 3
label:

	retry--
	response, err := emit.ClientBuilder(c.session).
		Context(ctx).
		Proxies(c.opts.proxies).
		Option(c.connOpts).
		POST("https://www.coze.com/api/draftbot/get_bot_info").
		Query("msToken", c.msToken).
		Header("user-agent", userAgent).
		Header("cookie", c.makeCookie()).
		Header("origin", "https://www.coze.com").
		Header("referer", "https://www.coze.com/").
		JHeader().
		Body(map[string]string{
			"bot_id":   c.opts.BotId,
			"space_id": c.opts.version,
		}).
		DoC(emit.Status(http.StatusOK), emit.IsJSON)
	if err != nil {
		if retry > 0 {
			goto label
		}
		return
	}

	value, err = emit.ToMap(response)
	_ = response.Body.Close()
	if err != nil {
		if retry > 0 {
			goto label
		}
		return
	}

	if code, ok := value["code"].(float64); !ok || code != 0 {
		err = fmt.Errorf("fetch bot info failed: %s", value["msg"])
		if retry > 0 {
			goto label
		}
		return
	}

	value = value["data"].(map[string]interface{})
	info := value["work_info"].(map[string]interface{})
	j := info["other_info"].(string)
	if err = json.Unmarshal([]byte(j), &info); err != nil {
		if retry > 0 {
			goto label
		}
		return
	}

	value["model"] = info["model"].(string)
	return
}

func (c *Chat) DraftBot(ctx context.Context, info DraftInfo, system string) error {
	if info.TopP == 0 {
		info.TopP = 1
	}
	if info.Temperature == 0 {
		info.Temperature = 0.75
	}
	if info.MaxTokens == 0 {
		info.MaxTokens = 4096
	}

	if info.Model != "" && modelMap[info.Model] != "" {
		info.Model = modelMap[info.Model]
	}

	value, err := structToMap(info)
	if err != nil {
		return err
	}

	if isClaude(info.Model) {
		delete(value, "top_p")
		delete(value, "frequency_penalty")
		delete(value, "presence_penalty")
		delete(value, "response_format")
	}

	value["model_style"] = 0
	value["ShortMemPolicy"] = map[string]interface{}{
		"HistoryRound": 3,
	}

	valueBytes, err := json.Marshal(value)
	if err != nil {
		return err
	}

	payload := map[string]interface{}{
		"bot_id":   c.opts.BotId,
		"space_id": c.opts.version,
		"work_info": map[string]interface{}{
			"other_info": string(valueBytes),
		},
	}

	response, err := emit.ClientBuilder(c.session).
		Context(ctx).
		Proxies(c.opts.proxies).
		Option(c.connOpts).
		POST("https://www.coze.com/api/draftbot/update").
		Query("msToken", c.msToken).
		Header("user-agent", userAgent).
		Header("cookie", c.makeCookie()).
		Header("origin", "https://www.coze.com").
		Header("referer", "https://www.coze.com/").
		JHeader().
		Body(payload).
		DoC(emit.Status(http.StatusOK), emit.IsJSON)
	if err != nil {
		return err
	}

	value, err = emit.ToMap(response)
	_ = response.Body.Close()
	if err != nil {
		return err
	}

	if code, ok := value["code"].(float64); ok && code != 0 {
		return fmt.Errorf("update info failed: %s", value["msg"])
	}

	values := []map[string]interface{}{
		{"prompt_type": 1, "data": system, "record_id": ""},
		{"prompt_type": 2, "data": ""},
		{"prompt_type": 3, "data": ""},
	}
	valueBytes, err = json.Marshal(values)
	if err != nil {
		return err
	}

	payload = map[string]interface{}{
		"bot_id":   c.opts.BotId,
		"space_id": c.opts.version,
		"work_info": map[string]interface{}{
			"system_info_all": string(valueBytes),
		},
	}

	response, err = emit.ClientBuilder(c.session).
		Context(ctx).
		Proxies(c.opts.proxies).
		Option(c.connOpts).
		POST("https://www.coze.com/api/draftbot/update").
		Query("msToken", c.msToken).
		Header("user-agent", userAgent).
		Header("cookie", c.makeCookie()).
		Header("origin", "https://www.coze.com").
		Header("referer", "https://www.coze.com/").
		JHeader().
		Body(payload).
		DoC(emit.Status(http.StatusOK), emit.IsJSON)
	if err != nil {
		return err
	}

	value, err = emit.ToMap(response)
	_ = response.Body.Close()
	if err != nil {
		return err
	}

	if code, ok := value["code"].(float64); ok && code != 0 {
		return errors.New("update prompt failed")
	}

	return nil
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
	bogus, signature, err := c.sign("", payload)
	if err != nil {
		return "", err
	}

	fileBytes, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}

	// 1. 下载凭证
	response, err := emit.ClientBuilder(c.session).
		Proxies(c.opts.proxies).
		Context(ctx).
		Option(c.connOpts).
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
	_ = response.Body.Close()
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
	url, headers, err := c.uploadSign(ctx, struct {
		method          string
		sessionToken    string
		accessKeyId     string
		secretAccessKey string
		host            string
		serviceId       string
		headers         map[string]interface{}
		params          map[string]interface{}
		body            map[string]interface{}
	}{
		method:          "GET",
		sessionToken:    auth["session_token"].(string),
		accessKeyId:     auth["access_key_id"].(string),
		secretAccessKey: auth["secret_access_key"].(string),
		host:            host,
		serviceId:       serviceId,
		params: map[string]interface{}{
			"Action":        "ApplyImageUpload",
			"ServiceId":     serviceId,
			"FileSize":      len(fileBytes),
			"FileExtension": fileExt,
		},
	})
	if err != nil {
		return "", err
	}

	// 2.2 ApplyImageUpload
	response, err = emit.ClientBuilder(c.session).
		Proxies(c.opts.proxies).
		Context(ctx).
		Option(c.connOpts).
		GET(url).
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
	_ = response.Body.Close()
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
	url = fmt.Sprintf("https://%s/upload/v1/%s", uploadAddress["UploadHost"], storeInfo["StoreUri"])
	response, err = emit.ClientBuilder(c.session).
		Proxies(c.opts.proxies).
		Context(ctx).
		Option(c.connOpts).
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
	_ = response.Body.Close()
	if err != nil {
		return "", err
	}

	// throw error:  Mismatch CRC32 ???
	if code, ok := obj["code"]; !ok || code.(float64) != 2000 {
		return "", fmt.Errorf("upload failed: %s", obj["message"])
	}

	// 4.1 签名
	url, headers, err = c.uploadSign(ctx, struct {
		method          string
		sessionToken    string
		accessKeyId     string
		secretAccessKey string
		host            string
		serviceId       string
		headers         map[string]interface{}
		params          map[string]interface{}
		body            map[string]interface{}
	}{
		method:          "POST",
		sessionToken:    auth["session_token"].(string),
		accessKeyId:     auth["access_key_id"].(string),
		secretAccessKey: auth["secret_access_key"].(string),
		host:            host,
		serviceId:       serviceId,
		headers: map[string]interface{}{
			"Content-Type": "application/json",
		},
		params: map[string]interface{}{
			"Action":    "CommitImageUpload",
			"ServiceId": serviceId,
		},
		body: map[string]interface{}{
			"SessionKey": uploadAddress["SessionKey"],
		},
	})

	// 4.2 CommitImageUpload
	response, err = emit.ClientBuilder(c.session).
		Proxies(c.opts.proxies).
		Context(ctx).
		Option(c.connOpts).
		POST(url).
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
	_ = response.Body.Close()
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

	cookie += "i18next=en; "
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
		"bot_id":           c.opts.BotId,
		"conversation_id":  conversationId,
		"draft_mode":       false,
		"stream":           true,
		"chat_history":     make([]string, 0),
		"mention_list":     make([]string, 0),
		"device_id":        randDID(),
		"content_type":     t.String(),
	}

	if c.opts.owner {
		data["draft_mode"] = true
		data["space_id"] = c.opts.version
		delete(data, "bot_version")
	}

	return data
}

func (c *Chat) makeWebSdkPayload(ctx context.Context, t MessageType, histories []interface{}, query string) (map[string]interface{}, error) {
	if c.user == "" {
		response, err := emit.ClientBuilder(c.session).
			Context(ctx).
			Option(c.connOpts).
			Proxies(c.opts.proxies).
			GET("https://api.coze.com/open_api/v1/bot/onboarding").
			Query("source", "web_sdk").
			Query("bot_id", c.opts.BotId).
			Query("msToken", c.msToken).
			DoC(emit.Status(http.StatusOK), emit.IsJSON)
		if err != nil {
			return nil, err
		}

		obj, err := emit.ToMap(response)
		_ = response.Body.Close()
		if err != nil {
			return nil, err
		}
		if code, ok := obj["code"].(float64); ok && code != 0 {
			return nil, fmt.Errorf("%v", obj["msg"])
		}

		c.user = obj["user_id"].(string)
	}

	data := map[string]interface{}{
		"query":            query,
		"local_message_id": randHex(21),
		"extra":            make(map[string]string),
		"scene":            c.opts.scene,
		"bot_id":           c.opts.BotId,
		"conversation_id":  randHex(21),
		"draft_mode":       false,
		"stream":           true,
		"chat_history":     histories,
		"mention_list":     make([]string, 0),
		"device_id":        randDID(),
		"content_type":     t.String(),
		"user":             c.user,
	}
	return data, nil
}

func (c *Chat) uploadSign(ctx context.Context, auth struct {
	method          string
	sessionToken    string
	accessKeyId     string
	secretAccessKey string
	host            string
	serviceId       string
	headers         map[string]interface{}
	params          map[string]interface{}
	body            map[string]interface{}
}) (url string, headers map[string]interface{}, err error) {
	var query string
	var action string
	for k, v := range auth.params {
		if k == "Action" {
			action = v.(string)
		}
		query += fmt.Sprintf("%s=%v&", k, v)
	}
	if query == "" {
		return "", nil, errors.New("empty auth.params")
	}
	if action == "" {
		return "", nil, errors.New("empty action")
	}

	query += "Version=2018-08-01"
	auth.params["Version"] = "2018-08-01"
	obj := map[string]interface{}{
		"method":   auth.method,
		"url":      "https://" + auth.host + "/?" + query,
		"timeout":  30000,
		"pathname": "/",
		"region":   "ap-singapore-1",
		"params":   auth.params,
	}

	if auth.headers != nil {
		obj["headers"] = auth.headers
	}

	if auth.body != nil {
		bodyBytes, _ := json.Marshal(auth.body)
		obj["custom"] = string(bodyBytes)
		obj["body"] = auth.body
	}

	response, err := emit.ClientBuilder(c.session).
		//Proxies(c.opts.proxies).
		Context(ctx).
		Option(c.connOpts).
		POST(SignURL+"/upload-sign").
		Query("mime", "imagex").
		Query("accessKeyId", auth.accessKeyId).
		Query("secretAccessKey", auth.secretAccessKey).
		Query("sessionToken", auth.sessionToken).
		JHeader().
		Body(obj).
		DoS(http.StatusOK)
	if err != nil {
		return
	}

	obj, err = emit.ToMap(response)
	_ = response.Body.Close()
	if err != nil {
		return
	}

	if o, ok := obj["ok"]; !ok || !reflect.DeepEqual(o, true) {
		return "", nil, fmt.Errorf("upload sign failed: %s", obj["msg"])
	}

	obj = obj["data"].(map[string]interface{})
	request := obj["request"].(map[string]interface{})
	headers = request["headers"].(map[string]interface{})
	url = strings.Replace(request["url"].(string), ".com/?", ".com?", -1)
	return
}

// bogus: X-Bogus
// signature: _signature
func (c *Chat) sign(uri string, payload interface{}) (string, string, error) {
	response, err := emit.ClientBuilder(c.session).
		//Proxies(proxies).
		Option(c.connOpts).
		POST(SignURL).
		Query("msToken", c.msToken).
		Query("uri", url.QueryEscape(uri)).
		JHeader().
		Body(payload).
		DoS(http.StatusOK)
	if err != nil {
		return "", "", fmt.Errorf("coze-sign: %v", err)
	}

	defer response.Body.Close()
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
	response, err := emit.ClientBuilder(c.session).
		//Proxies(c.opts.proxies).
		Option(c.connOpts).
		GET(SignURL + "/report").
		DoS(http.StatusOK)
	if err != nil {
		return "", err
	}

	var res signResponse[map[string]interface{}]
	err = emit.ToObject(response, &res)
	_ = response.Body.Close()
	if err != nil {
		return "", err
	}

	if !res.Ok {
		return "", errors.New("refresh msToken failed")
	}

	u := res.Data["url"]
	if c.webSdk {
		u = "https://mssdk-i18n-sg.ciciai.com"
	}

	delete(res.Data, "url")
	response, err = emit.ClientBuilder(c.session).
		Proxies(c.opts.proxies).
		Option(c.connOpts).
		POST(fmt.Sprintf("%s/web/report", u)).
		Query("msToken", c.msToken).
		JHeader().
		Body(res.Data).
		DoS(http.StatusOK)
	if err != nil {
		return "", err
	}

	logrus.Infof("%s", emit.TextResponse(response))
	_ = response.Body.Close()

	cookie := emit.GetCookie(response, "msToken")
	if cookie == "" {
		return cookie, errors.New("refresh msToken failed")
	}
	// fmt.Printf("msToken success: %s\n", cookie)
	return cookie, nil
}

func (c *Chat) GetSpace(ctx context.Context) (space string, err error) {
	if c.space != "" {
		return c.space, nil
	}

	response, err := emit.ClientBuilder(c.session).
		Proxies(c.opts.proxies).
		Context(ctx).
		POST("https://www.coze.com/api/space/list").
		Query("msToken", c.msToken).
		Header("user-agent", userAgent).
		Header("cookie", c.makeCookie()).
		Header("origin", "https://www.coze.com").
		Header("referer", "https://www.coze.com/space/").
		JHeader().
		Body(map[string]interface{}{}).
		DoC(emit.Status(http.StatusOK), emit.IsJSON)
	if err != nil {
		return
	}
	defer response.Body.Close()

	obj, err := emit.ToMap(response)
	if err != nil {
		return "", err
	}

	if code, ok := obj["code"].(float64); !ok || code != 0 {
		return "", errors.New(obj["msg"].(string))
	}

	list := obj["bot_space_list"].([]interface{})
	if len(list) == 0 {
		return "", errors.New("space no found [bot_space_list = 0]")
	}

	for _, value := range list {
		if str, ok := value.(map[string]interface{})["id"].(string); ok {
			c.space = str
			return str, nil
		}
	}

	return "", errors.New("space no found")
}

func (c *Chat) getCon() (conversationId string, err error) {
	obj := map[string]interface{}{
		"cursor":                      "0",
		"count":                       15,
		"draft_mode":                  false,
		"bot_id":                      c.opts.BotId,
		"scene":                       c.opts.scene,
		"biz_kind":                    "",
		"insert_history_message_list": make([]string, 0),
	}

	response, err := emit.ClientBuilder(c.session).
		Proxies(c.opts.proxies).
		Option(c.connOpts).
		POST(fmt.Sprintf("%s/get_message_list", BaseURL)).
		Query("msToken", c.msToken).
		Header("user-agent", userAgent).
		Header("cookie", c.makeCookie()).
		Header("origin", "https://www.coze.com").
		Header("referer", "https://www.coze.com/store/bot").
		JHeader().
		Body(obj).
		DoC(emit.Status(http.StatusOK), emit.IsJSON)
	if err != nil {
		return
	}
	defer response.Body.Close()

	obj, err = emit.ToMap(response)
	_ = response.Body.Close()
	if err != nil {
		return "", err
	}

	if code, ok := obj["code"].(float64); ok && code == 0 {
		conversationId = obj["conversation_id"].(string)
		return
	}

	return "", fmt.Errorf("%s", obj["msg"])
}

func (c *Chat) createSection(conversationId string) {
	if conversationId == "" {
		return
	}

	response, err := emit.ClientBuilder(c.session).
		Proxies(c.opts.proxies).
		Option(c.connOpts).
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
		logrus.Errorf("createSection [%s] failed: %v\n", conversationId, err)
		return
	}

	logrus.Infof("%s\n", emit.TextResponse(response))
	_ = response.Body.Close()
}

func (c *Chat) delCon(conversationId string) {
	if conversationId == "" {
		return
	}

	response, err := emit.ClientBuilder(c.session).
		Proxies(c.opts.proxies).
		Option(c.connOpts).
		POST(fmt.Sprintf("%s/clear_message", BaseURL)).
		Query("msToken", c.msToken).
		Header("user-agent", userAgent).
		Header("cookie", c.makeCookie()).
		Header("origin", "https://www.coze.com").
		Header("referer", "https://www.coze.com/store/bot").
		JHeader().
		Body(map[string]any{
			"bot_id":          c.opts.BotId,
			"conversation_id": conversationId,
			"scene":           c.opts.scene,
		}).
		DoS(http.StatusOK)
	if err != nil {
		logrus.Errorf("delCon [%s] failed: %v\n", conversationId, err)
		return
	}

	logrus.Infof("%s\n", emit.TextResponse(response))
	_ = response.Body.Close()
}

func (c *Chat) resolve(ctx context.Context, conversationId string, response *http.Response, ch chan string) {
	prefix := []byte("data:")
	errorPrefix := []byte("{\"code\":")
	defer close(ch)
	defer response.Body.Close()
	if !c.webSdk {
		defer c.delCon(conversationId)
	}

	m10 := 10 * 1024 * 1024 // bufio.Scanner: token too long ?
	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 1024), m10)
	scanner.Split(func(data []byte, eof bool) (advance int, token []byte, err error) {
		if eof && len(data) == 0 {
			return 0, nil, nil
		}
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			return i + 1, data[0:i], nil
		}
		if eof {
			return len(data), data, nil
		}
		return 0, nil, nil
	})

	// true 继续，false 结束
	Do := func() bool {
		if !scanner.Scan() {
			return false
		}

		var event string
		data := scanner.Text()
		logrus.Trace("--------- ORIGINAL MESSAGE ---------")
		logrus.Trace(data)
		if data == "" {
			return true
		}

		if len(data) < 6 || data[:6] != "event:" {
			return true
		}
		event = strings.TrimSpace(data[6:])
		if event == "done" {
			return false
		}

		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				ch <- fmt.Sprintf("error: %v", err)
			}
			return false
		}

		dataBytes := scanner.Bytes()
		logrus.Tracef("--------- ORIGINAL MESSAGE ---------")
		logrus.Tracef("%s", dataBytes)

		if bytes.HasPrefix(dataBytes, errorPrefix) {
			ch <- fmt.Sprintf("error: %s", dataBytes)
			return false
		}

		if !bytes.HasPrefix(dataBytes, prefix) {
			return true
		}

		dataBytes = bytes.TrimPrefix(dataBytes, prefix)
		if len(dataBytes) == 0 {
			return true
		}

		var msg resMessage
		err := json.Unmarshal(dataBytes, &msg)
		if err != nil {
			logrus.Errorf("unmarshal response failed: %v", err)
			return true
		}

		if msg.Message.Role == "assistant" {
			if msg.Message.Type == "answer" {
				if IsLimit(msg.Message.Content) {
					ch <- fmt.Sprintf("error: %v", msg.Message.Content)
					return false
				}
				ch <- fmt.Sprintf("text: %s", msg.Message.Content)
			}
			if msg.Message.Type == "tool_response" && strings.HasPrefix(msg.Message.Content, "Failed:") {
				ch <- fmt.Sprintf("error: %v", msg.Message.Content)
				return false
			}
		}
		return true
	}

	for {
		select {
		case <-ctx.Done():
			ch <- "error: context done"
			return
		default:
			if stop := !Do(); stop {
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

func (c *Chat) TransferMessages(messages []Message) (result []interface{}) {
	result = make([]interface{}, 0)
	condition := func(role string) string {
		switch role {
		case "assistant":
			return role
		default:
			return "user"
		}
	}

	for index, message := range messages {
		mid := randDID()
		messageT := "ack"
		if message.Role == "assistant" {
			messageT = "answer"
		}

		result = append(result, map[string]interface{}{
			"bot_id":       c.opts.BotId,
			"content":      message.Content,
			"content_obj":  message.Content,
			"content_type": "text",
			"extra_info": map[string]string{
				"local_message_id": randHex(21),
				// more ...
			},
			"index":        index,
			"is_finish":    true,
			"logId":        "20240607005905BF4F17BE43B37D011A9A",
			"mention_list": make([]string, 0),
			"message_id":   mid,
			"preset_bot":   "",
			"reply_id":     mid,
			"role":         condition(message.Role),
			"section_id":   "999",
			"broken_pos":   9999999,
			"type":         messageT,
			"_fromHistory": true,
		})
	}
	return
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

func structToMap(obj interface{}) (value map[string]interface{}, err error) {
	objBytes, err := json.Marshal(obj)
	if err != nil {
		return
	}
	err = json.Unmarshal(objBytes, &value)
	return
}

func isClaude(model string) bool {
	return model == ModelClaude35Sonnet_200k ||
		model == ModelClaude3Haiku_200k ||
		model == modelMap[ModelClaude35Sonnet_200k] ||
		model == modelMap[ModelClaude3Haiku_200k]
}
