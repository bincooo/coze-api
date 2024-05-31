package coze

type Chat struct {
	cookie  string
	msToken string
	opts    Options
}

type Options struct {
	botId   string // 机器人Id
	version string // 机器人版本
	scene   int    // 场景？？
	proxies string // 本地代理
	spaceId string //
}

type Message struct {
	Role    string
	Content string
}

type resMessage struct {
	MessageId string `json:"message_id"`
	ReplyId   string `json:"reply_id"`

	Message struct {
		Role    string `json:"role"`
		Type    string `json:"type"`
		Content string `json:"content"`
	} `json:"message"`
}

type signResponse[T any] struct {
	Ok   bool
	Msg  string
	Data T
}

type DraftInfo struct {
	Model            string  `json:"model"`
	Temperature      float64 `json:"temperature"`
	TopP             int     `json:"top_p"`
	FrequencyPenalty int     `json:"frequency_penalty"`
	PresencePenalty  int     `json:"presence_penalty"`
	MaxTokens        int     `json:"max_tokens"`
	ResponseFormat   int     `json:"response_format"` // 0 Text 1 Markdown 2 JSON
}
