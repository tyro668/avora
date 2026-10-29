package conformance

import (
	"fmt"
	"strings"

	"github.com/tyro668/avora/internal/lmbp"
)

// Requirement is one stable, numbered requirement of the spec (§13.2) and
// the conformance checks that verify it. Requirement IDs and check IDs never
// change meaning; retired IDs are not reused.
type Requirement struct {
	ID      string
	Section string
	Profile string
	Text    string
	Checks  []string
}

// Catalog is the single source of the requirement ↔ check mapping. The table
// in docs/lmbp-spec.md §13.2 is `lmbp-conformance -list` verbatim
// (spec/validate.sh compares them).
var Catalog = []Requirement{
	{"CORE-01", "§5.2", lmbp.ProfileCore, "JWS 严格校验：头只含 alg/typ/kid，alg 为 EdDSA，typ 匹配用途，kid 为公钥指纹，声明类型正确", []string{"Z4a", "Z4b"}},
	{"CORE-02", "§6.1、§18.2", lmbp.ProfileCore, "发现与元数据：JWKS、issuer 同源且来自配置（伪造 Host 不改变 issuer）、protocol_versions 含 2.0、profiles 含 core", []string{"S0", "D1", "M1", "M2", "M3", "M6", "M8", "M9"}},
	{"CORE-03", "§19.1", lmbp.ProfileCore, "带 ?tenant= 的元数据带网关签名的 SaaS 身份", []string{"M4", "M5", "M7"}},
	{"CORE-04", "§6.2", lmbp.ProfileCore, "设备授权：表单编码、user_code 格式、no-store、device_name ≤ 100 码点且不含控制与双向格式字符、未注册租户 invalid_client", []string{"P1", "P2", "P3", "L1", "L4", "P9"}},
	{"CORE-05", "§6.3", lmbp.ProfileCore, "令牌端点：先验证明再透露状态，device_code 一次性，无视 slow_down 超过 10 次后 expired_token", []string{"P4", "P5", "T5", "P13"}},
	{"CORE-06", "§6.4", lmbp.ProfileCore, "租户确认配对：未知码 404，jkt 不符 409，忽略大小写与分隔符；待确认配对从不列出，确认一次性，失败按终端用户计数", []string{"P6", "P7", "P8", "P10", "P11", "P12"}},
	{"CORE-07", "§5.3、§18.3", lmbp.ProfileCore, "访问令牌：at+jwt，iss/aud/tenant/sub/cnf.jkt 正确，与 JWKS、元数据一致", []string{"T1", "T2", "T3", "T4", "I1", "I2"}},
	{"CORE-08", "§5.5", lmbp.ProfileCore, "客户端断言：aud 为本网关令牌端点，jti 防重放", []string{"T6", "T7", "I3"}},
	{"CORE-09", "§7.1", lmbp.ProfileCore, "WebSocket 升级：要求子协议 lmbp（名字不带版本号，带版本号的变体被拒绝），令牌无效 401，选择 lmbp", []string{"W1", "W2", "W4", "W8"}},
	{"CORE-10", "§7.4、§11", lmbp.ProfileCore, "1.x 对端被拒：子协议仍为 lmbp，v 为 1 的 hello 回 error VERSION_UNSUPPORTED 后断开", []string{"W9"}},
	{"CORE-11", "§7.4", lmbp.ProfileCore, "hello 校验：证明绑定本连接令牌，符合 hello.json，max_concurrency 越界拒绝不截断", []string{"W3", "W10", "W11"}},
	{"CORE-12", "§7.4、§11", lmbp.ProfileCore, "welcome：同 id，能力取交集（任意交集都合法），max_concurrency 在 1 与声明值之间", []string{"W5", "W6", "W12", "X1"}},
	{"CORE-13", "§7.2、§7.3", lmbp.ProfileCore, "帧：只发文本帧，符合 envelope.json，未知 type 不断开，握手后 v≠2 的帧回 BAD_REQUEST", []string{"F0", "F1", "F2", "W7"}},
	{"CORE-14", "§7.4", lmbp.ProfileCore, "models.update：不符合 models.update.json 时整帧拒绝、不生效；提高 max_concurrency 立即按 FIFO 启动排队请求", []string{"W13", "Q1"}},
	{"CORE-15", "§5.6、§7.5", lmbp.ProfileCore, "task.run：无 data，JWS 可验证，载荷正确，envelope seq 为 1", []string{"R1", "R2", "R3"}},
	{"CORE-16", "§7.7", lmbp.ProfileCore, "连接内续期 session.token", []string{"K1"}},
	{"CORE-17", "§8.2", lmbp.ProfileCore, "吊销立即断开会话，之后不能取得令牌；进行中的任务以 502 OUTCOME_UNKNOWN 结束", []string{"V1", "V2", "V3"}},
	{"CORE-18", "§6.6", lmbp.ProfileCore, "在线设备未声明的模型返回 404 MODEL_NOT_FOUND", []string{"E1"}},
	{"CORE-19", "§6", lmbp.ProfileCore, "JSON 响应带 Cache-Control: no-store", []string{"E2"}},
	{"CORE-20", "§10", lmbp.ProfileCore, "限制：messages 1–200 条，帧按 UTF-8 字节计、≤ 262144，单任务输出 ≤ 64 MiB（超出 task.cancel(protocol_error)）", []string{"Z6a", "Z6b", "Z6c", "Z6d", "Z6e", "Z6f", "Z6g", "Z9"}},
	{"CORE-21", "§4.1", lmbp.ProfileCore, "X-End-User 为 1–128 个可打印 ASCII 字符", []string{"L2"}},
	{"CORE-22", "§8.6", lmbp.ProfileCore, "确认属于 Core，不依赖 flow：按序数据帧累计确认，跳号让任务失败，本地结束的任务迟到帧照常确认直到终止帧；未知或已结束任务的数据帧回 task.cancel(unknown_task)，不确认", []string{"S1", "S2", "S3", "S4", "S5", "E7"}},
	{"CORE-23", "§16.1", lmbp.ProfileCore, "model_names 只用于展示，未声明模型的条目被忽略", []string{"X-N1"}},
	{"CORE-24", "§8.6", lmbp.ProfileCore, "设备数据帧先校验信封与正文（task.done/task.error 须符合各自 Schema），再接受序号、持久化和确认；非法终止帧让任务失败（task.cancel protocol_error），不确认", []string{"S6"}},
	{"REL-01", "§14、§15", lmbp.ProfileReliable, "协商 resume 与 flow；协商后确认同样覆盖全部数据帧，网关数据帧（含 blob.chunk）连续编号，续传后跳号仍让任务失败", []string{"X1r", "X-F1", "X-F2", "X-F3"}},
	{"REL-02", "§14.2–§14.3", lmbp.ProfileReliable, "断线续传：重传不重复、不丢失，续传参数有界", []string{"X-R1", "X-R2", "Z3"}},
	{"REL-03", "§14.4", lmbp.ProfileReliable, "SSE 事件带 id，Last-Event-ID 精确重放", []string{"X-H2", "X-H3"}},
	{"REL-04", "§14.4", lmbp.ProfileReliable, "幂等：同键同体接回，异体 422，按租户和终端用户隔离，排队中的重复请求接回，键为 1–255 个可打印 ASCII", []string{"X-H1", "X-H4", "Z1", "Z1b", "Z7", "L3"}},
	{"REL-05", "§14.4", lmbp.ProfileReliable, "保留期清理已结束任务及其幂等记录", []string{"E6"}},
	{"REL-06", "§15", lmbp.ProfileReliable, "流量控制：窗口 ≥ max_frame_bytes，并发下不超窗", []string{"Z2", "Z6h", "Z6i"}},
	{"TOOLS-01", "§16.1", lmbp.ProfileTools, "tools：协商 tools，每模型能力、签名载荷携带、tool_calls 合并、缺能力 400，index 超出 0–127 让任务失败", []string{"X1t", "X-T1", "X-T2", "X-T3", "X-T4", "X-T5"}},
	{"MM-01", "§16.2–§16.3", lmbp.ProfileMultimodal, "内容片段与 blob：协商 multimodal，缺 vision 400，大 data: URI 走 blob.chunk", []string{"X1m", "X-M1", "X-M2"}},
	{"MM-02", "§16.2", lmbp.ProfileMultimodal, "远程图片原样转发，设备不支持时调用方得到 400 CAPABILITY_UNSUPPORTED", []string{"E4"}},
	{"E2EE-01", "§17", lmbp.ProfileE2EE, "端到端加密：协商 e2ee，密钥声明、JWE 原样转发、密封输出", []string{"X1e", "X-E1", "X-E2", "X-E3", "X-E4", "X-E5"}},
	{"OAI-01", "§6.5", lmbp.ProfileOpenAI, "/v1/models 与 SSE 输出", []string{"O1", "O2"}},
	{"OAI-02", "§6.5", lmbp.ProfileOpenAI, "调用方断开（流式与非流式）后向设备发送 task.cancel", []string{"C1", "E3"}},
	{"OAI-03", "§6.5", lmbp.ProfileOpenAI, "请求参数校验，共享向量 params.json（长度按码点）", []string{"Z8a", "Z8b", "Z8c"}},
	{"OAI-04", "§16.4", lmbp.ProfileOpenAI, "声明了 params 的模型：未声明的参数 400 CAPABILITY_UNSUPPORTED", []string{"Z8d"}},
	{"OAI-05", "§16.5", lmbp.ProfileOpenAI, "被忽略的字段不写入 task.run", []string{"E5"}},
	{"ANT-01", "§6.7", lmbp.ProfileAnthropic, "Anthropic Messages 兼容接口", []string{"A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "A10", "Z5", "E1b"}},
}

var checkIndex = func() map[string]Requirement {
	m := map[string]Requirement{}
	for _, r := range Catalog {
		for _, c := range r.Checks {
			if _, dup := m[c]; dup {
				panic("check " + c + " mapped twice")
			}
			m[c] = r
		}
	}
	return m
}()

// RequirementOf returns the requirement a check verifies.
func RequirementOf(check string) (Requirement, bool) { r, ok := checkIndex[check]; return r, ok }

// CatalogMarkdown renders the §13.2 table.
func CatalogMarkdown() string {
	var b strings.Builder
	b.WriteString("| 需求 ID | 条款 | 配置 | 要求 | conformance 检查 |\n|---|---|---|---|---|\n")
	for _, r := range Catalog {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", r.ID, r.Section, r.Profile, r.Text, strings.Join(r.Checks, " "))
	}
	return b.String()
}
