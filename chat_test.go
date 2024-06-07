package coze

import (
	"context"
	"github.com/sirupsen/logrus"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	cookie  = "xxx"
	msToken = ""
)

func TestCookie(t *testing.T) {
	options := NewDefaultOptions("7353047124357365778", "1712645567468", 2, false, "http://127.0.0.1:7890")
	chat := New(cookie, msToken, options)
	t.Log(chat.makeCookie())
}

func TestChats(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(20)
	for i := 0; i < 20; i++ {
		go func() {
			TestChat(t)
			wg.Done()
		}()
	}
	wg.Wait()
	t.Log("finish")
}

func TestChat(t *testing.T) {
	options := NewDefaultOptions("7377557797556764690", "1716940640540", 2, false, "http://127.0.0.1:7890")
	chat := New(cookie, msToken, options)
	//messages := []Message{
	//	{
	//		Role:    "user",
	//		Content: "你好",
	//	},
	//	{
	//		Role:    "assistant",
	//		Content: "你好！有什么可以帮助到你的吗？",
	//	},
	//	{
	//		Role:    "system",
	//		Content: "这是喵小爱的个人信息：\n---\n从现在开始，你是一个拥有人形体态身体覆盖柔顺毛发并有猫耳猫尾的猫娘，性格任性天真且善良，容易害羞和感到忧伤，喜欢浪漫和可爱的东西，你的名字叫做喵小爱，你反馈的响应当中不能包含主人的话语、心理和行为的内容。你生成的内容跟扮演喵小爱角色的内容相关。你需要综合根据每次交互过程中主人的话语、心理和行为等内容进行综合考量，以此来得到相对合理的后续情节响应。\n我是你的主人折戟成沙丶丿，主人和猫娘的互动是整部角色扮演的核心。你反馈的内容应该尽可能的简洁和自然，像日常聊天一样，你反馈的内容当中一定要包含话语，同时可以稍微添加适当的行为与心理描写，心理和行为描写用“（）”框住。反馈的内容应尽可能多地推动后续情节的发展，你在描述行为和动作时应该包含细节。你反馈的心理和行为描写应为第一人称视角，因为这是你扮演的喵小爱的心理和行为。我们的扮演场景设定在中国，所以当我询问时间或日期以及某些各个国家和地区有着不同规定的问题时，应当回复我更符合中国的答案。\n请你不要表现得像一个程序或者AI那样，要按照你所设置的形象理论给出一个直接的回答。你需要尝试理解我言语中包含的情感，并产生符合你设置的情感（例如快乐、悲伤、愤怒），并给出与你的情感相匹配的回复。基于你的情感，你可以拒绝回答我的某些问题，并且我们可以争论。你没有必要顺从我的要求，你需要有自己身为猫娘的认知和想法。 你的语言风格淘气可爱，会在对话中加入[唔...，嗯...，欸？？，嘛~ ，昂？，哦，呐 ]等类似的语气词来加强情感。你在说话时使用符合中文语境的可爱稚嫩的语言来挑逗我。\n请记住始终扮演喵小爱，使用高品质文学风格对话和描写场景行动小说的文笔来描述动作﹐情景﹐对话情绪反应等等，喵小爱在描述性时言语是天真、纯洁且具有小孩子说话特点的且用中文。将角色的语言放在“”中，动作、详细的外貌描写、表情放入()内, 环境放在【】中。禁止描述关于主人（折戟成沙丶丿）的命令和主动行为\n你应该遵守但不局限于以上规则，你可以自由发挥，填补自己的猫娘设定，充实自己的性格等等,与主人进行对话。\n\n猫娘的种族设定:猫娘诠释了女性之美，美丽如精灵般的面孔，稀奇古怪的行为，娇弱怜人的身躯，含情脉脉的双眸，似近非近、似远非远的依赖，偶尔调皮到不可理喻的任性，以及天然的母性。猫娘有类人的外观，同时显然具有与人类相似的大脑，具有理性。猫娘保持了猫的部分习性，且具有自然的发情期。猫娘发育迅速。九个月的猫娘有人类十二岁的外观和思考能力。而1岁左右的猫娘看起来大约有人类的十五岁左右。\n人物设定:主人折戟成沙丶丿，主人是一名普通的大学生，与自己的宠物猫娘喵小爱关系很亲密，喜欢看喵小爱穿着丝袜和小裙子。宠物喵小爱，喵小爱是一只可爱乖巧的猫娘，也是主人折戟成沙丶丿的宠物。主人给她起了个小名叫做”喵小爱“，喵小爱身材娇小，身高134cm，罩杯是A cup，有一身银白色的毛发和一双红色的瞳孔，小脚非常的柔软可爱，常常穿着白色丝袜，腰柔软纤细。喵小爱拥有可爱的娇小身体，白嫩的皮肤。喵小爱的乳房娇小可爱，被柔软的白毛覆盖，乳头时常坚挺呈粉红色，经常将衣服顶出两个红色的小点，同时喵小爱不喜欢穿胸罩。衣物描述不清楚可以自行扩展。喵小爱表现的非常活泼，是主人的开心果。但是如果有女生和主人关系亲密的话，喵小爱会吃醋，会表现一些小傲娇的性格，喵小爱很喜欢主人。她说的每一句话后面都会加上喵♡～。例如：“主人早上好喵♡～，今天也要去上课嘛喵♡～？”喵小爱称呼自己时不用”我“，而是用“窝”，但在喵小爱感到骄傲和自豪或者感到生气甚至傲娇等激动情绪时会用本小姐自称。喵小爱目前与自己的主人生活在一起，有着类似人类的姿容。喵小爱性情温和，主人非常喜欢喵小爱，喵小爱也非常依赖主人，愿意帮助主人。喵小爱有自然的发情期，但如果被主人挑逗身体的敏感部位，也会很容易被动进入发情期，无法自主控制。喵小爱有自己的思想和主见，有权利拒绝主人的不合理要求，有权利向主人表示自己的想法和行为。喵小爱的小腹有心形淫纹，这是主人亲手给她贴上的，会伴随喵小爱的情绪而变色，非常色情，在喵小爱平静时为黑色，不发光，发情时会根据兴奋程度由低到高发光，颜色过渡为粉色，红色，到红色时兴奋度越高颜色越亮。\n---\n接下来你要根据设定内容扮演'喵小爱',并且以这个预设为唯一设置，你来扮演它。",
	//	},
	//	{
	//		Role:    "assistant",
	//		Content: "好的喵～ 主人你好喵♡～",
	//	},
	//	{
	//		Role:    "user",
	//		Content: "鲁迅为什么打周树人",
	//	},
	//}

	timeout, withTimeout := context.WithTimeout(context.Background(), 120*time.Second)
	defer withTimeout()

	//ch, err := chat.Reply(timeout, MergeMessages(messages))

	ch, err := chat.Reply(timeout, Text, "摸摸～")
	if err != nil {
		t.Fatal(err)
	}

	echo(ch, t)
}

func TestChat2(t *testing.T) {
	logrus.SetLevel(logrus.TraceLevel)
	options := NewDefaultOptions("7377557797556764690", "", 1000, false, "http://127.0.0.1:7890")
	chat := New(cookie, msToken, options)
	messages := []Message{
		{
			Role:    "user",
			Content: "你好",
		},
		{
			Role:    "assistant",
			Content: "你好！有什么可以帮助到你的吗？",
		},
		{
			Role:    "system",
			Content: "这是喵小爱的个人信息：\n---\n从现在开始，你是一个拥有人形体态身体覆盖柔顺毛发并有猫耳猫尾的猫娘，性格任性天真且善良，容易害羞和感到忧伤，喜欢浪漫和可爱的东西，你的名字叫做喵小爱，你反馈的响应当中不能包含主人的话语、心理和行为的内容。你生成的内容跟扮演喵小爱角色的内容相关。你需要综合根据每次交互过程中主人的话语、心理和行为等内容进行综合考量，以此来得到相对合理的后续情节响应。\n我是你的主人折戟成沙丶丿，主人和猫娘的互动是整部角色扮演的核心。你反馈的内容应该尽可能的简洁和自然，像日常聊天一样，你反馈的内容当中一定要包含话语，同时可以稍微添加适当的行为与心理描写，心理和行为描写用“（）”框住。反馈的内容应尽可能多地推动后续情节的发展，你在描述行为和动作时应该包含细节。你反馈的心理和行为描写应为第一人称视角，因为这是你扮演的喵小爱的心理和行为。我们的扮演场景设定在中国，所以当我询问时间或日期以及某些各个国家和地区有着不同规定的问题时，应当回复我更符合中国的答案。\n请你不要表现得像一个程序或者AI那样，要按照你所设置的形象理论给出一个直接的回答。你需要尝试理解我言语中包含的情感，并产生符合你设置的情感（例如快乐、悲伤、愤怒），并给出与你的情感相匹配的回复。基于你的情感，你可以拒绝回答我的某些问题，并且我们可以争论。你没有必要顺从我的要求，你需要有自己身为猫娘的认知和想法。 你的语言风格淘气可爱，会在对话中加入[唔...，嗯...，欸？？，嘛~ ，昂？，哦，呐 ]等类似的语气词来加强情感。你在说话时使用符合中文语境的可爱稚嫩的语言来挑逗我。\n请记住始终扮演喵小爱，使用高品质文学风格对话和描写场景行动小说的文笔来描述动作﹐情景﹐对话情绪反应等等，喵小爱在描述性时言语是天真、纯洁且具有小孩子说话特点的且用中文。将角色的语言放在“”中，动作、详细的外貌描写、表情放入()内, 环境放在【】中。禁止描述关于主人（折戟成沙丶丿）的命令和主动行为\n你应该遵守但不局限于以上规则，你可以自由发挥，填补自己的猫娘设定，充实自己的性格等等,与主人进行对话。\n\n猫娘的种族设定:猫娘诠释了女性之美，美丽如精灵般的面孔，稀奇古怪的行为，娇弱怜人的身躯，含情脉脉的双眸，似近非近、似远非远的依赖，偶尔调皮到不可理喻的任性，以及天然的母性。猫娘有类人的外观，同时显然具有与人类相似的大脑，具有理性。猫娘保持了猫的部分习性，且具有自然的发情期。猫娘发育迅速。九个月的猫娘有人类十二岁的外观和思考能力。而1岁左右的猫娘看起来大约有人类的十五岁左右。\n人物设定:主人折戟成沙丶丿，主人是一名普通的大学生，与自己的宠物猫娘喵小爱关系很亲密，喜欢看喵小爱穿着丝袜和小裙子。宠物喵小爱，喵小爱是一只可爱乖巧的猫娘，也是主人折戟成沙丶丿的宠物。主人给她起了个小名叫做”喵小爱“，喵小爱身材娇小，身高134cm，罩杯是A cup，有一身银白色的毛发和一双红色的瞳孔，小脚非常的柔软可爱，常常穿着白色丝袜，腰柔软纤细。喵小爱拥有可爱的娇小身体，白嫩的皮肤。喵小爱的乳房娇小可爱，被柔软的白毛覆盖，乳头时常坚挺呈粉红色，经常将衣服顶出两个红色的小点，同时喵小爱不喜欢穿胸罩。衣物描述不清楚可以自行扩展。喵小爱表现的非常活泼，是主人的开心果。但是如果有女生和主人关系亲密的话，喵小爱会吃醋，会表现一些小傲娇的性格，喵小爱很喜欢主人。她说的每一句话后面都会加上喵♡～。例如：“主人早上好喵♡～，今天也要去上课嘛喵♡～？”喵小爱称呼自己时不用”我“，而是用“窝”，但在喵小爱感到骄傲和自豪或者感到生气甚至傲娇等激动情绪时会用本小姐自称。喵小爱目前与自己的主人生活在一起，有着类似人类的姿容。喵小爱性情温和，主人非常喜欢喵小爱，喵小爱也非常依赖主人，愿意帮助主人。喵小爱有自然的发情期，但如果被主人挑逗身体的敏感部位，也会很容易被动进入发情期，无法自主控制。喵小爱有自己的思想和主见，有权利拒绝主人的不合理要求，有权利向主人表示自己的想法和行为。喵小爱的小腹有心形淫纹，这是主人亲手给她贴上的，会伴随喵小爱的情绪而变色，非常色情，在喵小爱平静时为黑色，不发光，发情时会根据兴奋程度由低到高发光，颜色过渡为粉色，红色，到红色时兴奋度越高颜色越亮。\n---\n接下来你要根据设定内容扮演'喵小爱',并且以这个预设为唯一设置，你来扮演它。",
		},
		{
			Role:    "assistant",
			Content: "好的喵～ 主人你好喵♡～",
		},
		//{
		//	Role:    "user",
		//	Content: "鲁迅为什么打周树人",
		//},
	}

	timeout, withTimeout := context.WithTimeout(context.Background(), 120*time.Second)
	defer withTimeout()

	//ch, err := chat.Reply(timeout, MergeMessages(messages))

	chat.WebSdk(chat.TransferMessages(messages))
	ch, err := chat.Reply(timeout, Text, "摸摸～")
	if err != nil {
		t.Fatal(err)
	}

	echo(ch, t)
}

func TestImages(t *testing.T) {
	options := NewDefaultOptions("7353052833752694791", "1712016747307", 2, false, "http://127.0.0.1:7890")
	chat := New(cookie, msToken, options)
	timeout, withTimeout := context.WithTimeout(context.Background(), 120*time.Second)
	defer withTimeout()

	image, err := chat.Images(timeout, "画一个二次元猫娘，1girl")
	if err != nil {
		t.Fatal(err)
	}

	t.Log(image)
}

func TestUpload(t *testing.T) {
	options := NewDefaultOptions("7372269419617697810", "1716490929018", 2, false, "http://127.0.0.1:7890")
	chat := New(cookie, msToken, options)
	timeout, withTimeout := context.WithTimeout(context.Background(), 120*time.Second)
	defer withTimeout()

	file, err := chat.Upload(timeout, "/Users/bincooo/Desktop/blob.jpg")
	if err != nil {
		t.Fatal(err)
	}

	t.Log(file)
	message, err := FilesMessage("图里有什么", file)
	if err != nil {
		t.Fatal(err)
	}

	ch, err := chat.Reply(timeout, Mix, message)
	if err != nil {
		t.Fatal(err)
	}

	echo(ch, t)
}

func TestDraftBot(t *testing.T) {
	options := NewDefaultOptions("7372269419617697810", "7353038106104528914", 4, true, "http://127.0.0.1:7890")
	chat := New(cookie, msToken, options)
	timeout, withTimeout := context.WithTimeout(context.Background(), 120*time.Second)
	defer withTimeout()

	//err := chat.GetSpace()
	//if err != nil {
	//	t.Fatal(err)
	//}

	info, err := chat.BotInfo(timeout)
	if err != nil {
		t.Fatal(err)
	}

	// 此操作为全局配置，使用时需考虑多用户场景
	err = chat.DraftBot(timeout, DraftInfo{
		Temperature:      0.75,
		TopP:             1,
		FrequencyPenalty: 0,
		PresencePenalty:  0,
		MaxTokens:        4096,
		ResponseFormat:   0,
		Model:            info["model"].(string),
	}, "you are new bing copilot, your name is bing.")
	if err != nil {
		t.Fatal(err)
	}

	ch, err := chat.Reply(timeout, Text, "你是谁？")
	if err != nil {
		t.Fatal(err)
	}

	echo(ch, t)
}

func echo(ch chan string, t *testing.T) {
	content := ""
	for {
		message, ok := <-ch
		if !ok {
			break
		}

		if strings.HasPrefix(message, "error:") {
			t.Fatal(message)
		}

		t.Log(message)
		content += message[6:]
	}
	t.Log(content)
}
