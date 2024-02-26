package coze

type Chat struct {
	cookie  string
	msToken string
	opts    Options
}

type Options struct {
	botId   string // 机器人Id
	scene   int    // 场景？？
	proxies string // 本地代理
}

type Message struct {
	Role    string
	Content string
}

type resMessage struct {
	Message struct {
		Role    string `json:"role"`
		Type    string `json:"type"`
		Content string `json:"content"`
	} `json:"message"`
}
