// Package saas is the mock business service (the role of the missing
// sophorn-mock-server): user login, the "link a device" page where a signed-in
// user types the code shown by the desktop connector, a device list, and a
// chat page whose backend proxies the gateway's OpenAI-compatible stream.
// The tenant API key stays server-side; browsers only hold a session cookie.
package saas

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/tyro668/avora/internal/lmbp"
)

type Config struct {
	PublicURL        string // this service's external origin (used in link_url)
	GatewayURL       string // gateway as reached from this backend
	PublicGatewayURL string // gateway as reached from desktops (defaults to GatewayURL)
	TenantID         string
	TenantAPIKey     string
	Users            map[string]string // user → password (mock only)
}

type Server struct {
	cfg      Config
	mu       sync.Mutex
	sessions map[string]string
	// pins records, per user, the device key thumbprint (jkt) received through
	// the pairing link; it anchors trust in the device's E2EE key.
	pins   map[string]map[string]string
	client *http.Client
}

func New(cfg Config) *Server {
	if cfg.PublicGatewayURL == "" {
		cfg.PublicGatewayURL = cfg.GatewayURL
	}
	return &Server{cfg: cfg, sessions: map[string]string{}, pins: map[string]map[string]string{}, client: &http.Client{}}
}

func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc(lmbp.DiscoveryPath, s.discovery)
	m.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"status":"ok"}`)) })
	m.HandleFunc("/login", s.login)
	m.HandleFunc("/logout", s.logout)
	m.HandleFunc("/", s.auth(s.home))
	m.HandleFunc("/link", s.auth(s.link))
	m.HandleFunc("/api/devices", s.auth(s.proxy("GET", "/lmbp/v1/tenant/devices")))
	m.HandleFunc("/api/models", s.auth(s.proxy("GET", "/v1/models")))
	m.HandleFunc("/api/chat", s.auth(s.proxy("POST", "/v1/chat/completions")))
	m.HandleFunc("/api/chat/e2ee", s.auth(s.e2eeChat))
	m.HandleFunc("/api/devices/revoke", s.auth(s.revoke))
	return m
}

// discovery is public and contains no secrets and no codes.
func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"gateway_url": s.cfg.PublicGatewayURL, "tenant": s.cfg.TenantID, "link_url": strings.TrimRight(s.cfg.PublicURL, "/") + "/link", "protocol": "lmbp"})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		page.ExecuteTemplate(w, "login", map[string]string{"Next": r.URL.Query().Get("next")})
		return
	}
	u, p := r.FormValue("user"), r.FormValue("password")
	want, ok := s.cfg.Users[u]
	if !ok || subtle.ConstantTimeCompare([]byte(want), []byte(p)) != 1 {
		w.WriteHeader(401)
		page.ExecuteTemplate(w, "login", map[string]string{"Error": "用户名或密码错误"})
		return
	}
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	sid := hex.EncodeToString(b)
	s.mu.Lock()
	s.sessions[sid] = u
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: time.Now().Add(12 * time.Hour)})
	next := r.FormValue("next")
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("sid"); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

type userHandler func(w http.ResponseWriter, r *http.Request, user string)

func (s *Server) auth(h userHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := ""
		if c, err := r.Cookie("sid"); err == nil {
			s.mu.Lock()
			user = s.sessions[c.Value]
			s.mu.Unlock()
		}
		if user == "" {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, `{"error":{"message":"login required","code":"UNAUTHENTICATED"}}`, 401)
				return
			}
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}
		// CSRF: SameSite=Strict cookie plus an Origin check on state-changing requests.
		if r.Method != http.MethodGet {
			if o := r.Header.Get("Origin"); o != "" && o != strings.TrimRight(s.cfg.PublicURL, "/") {
				http.Error(w, "cross-origin request rejected", 403)
				return
			}
		}
		h(w, r, user)
	}
}

func (s *Server) gw(r *http.Request, method, path string, body io.Reader, user string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(r.Context(), method, s.cfg.GatewayURL+path, body)
	if err != nil {
		return nil, err
	}
	for _, h := range []string{"Idempotency-Key", "Last-Event-ID"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.TenantAPIKey)
	req.Header.Set("X-End-User", user) // identity comes from our session, never from the browser
	req.Header.Set("Content-Type", "application/json")
	return s.client.Do(req)
}

// proxy forwards to the gateway and streams the response through unbuffered.
func (s *Server) proxy(method, path string) userHandler {
	return func(w http.ResponseWriter, r *http.Request, user string) {
		if r.Method != method {
			http.Error(w, "method not allowed", 405)
			return
		}
		var body io.Reader
		if method == http.MethodPost {
			body = http.MaxBytesReader(w, r.Body, 40<<20) // images travel inline as data: URIs
		}
		resp, err := s.gw(r, method, path, body, user)
		if err != nil {
			http.Error(w, `{"error":{"message":"gateway unreachable","code":"DEVICE_OFFLINE"}}`, 502)
			return
		}
		defer resp.Body.Close()
		for _, h := range []string{"Content-Type", "Cache-Control", "X-Task-Id", "Retry-After"} {
			if v := resp.Header.Get(h); v != "" {
				w.Header().Set(h, v)
			}
		}
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(resp.StatusCode)
		f, _ := w.(http.Flusher)
		buf := make([]byte, 4096)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
				if f != nil {
					f.Flush()
				}
			}
			if err != nil {
				return
			}
		}
	}
}

func (s *Server) link(w http.ResponseWriter, r *http.Request, user string) {
	data := map[string]any{"User": user, "Code": r.URL.Query().Get("user_code"), "JKT": r.URL.Query().Get("jkt")}
	if r.Method == http.MethodPost {
		jkt := r.FormValue("jkt")
		b, _ := json.Marshal(map[string]any{"user_code": r.FormValue("user_code"), "deny": r.FormValue("deny") == "1", "jkt": jkt})
		resp, err := s.gw(r, "POST", "/lmbp/v1/tenant/devices/approvals", strings.NewReader(string(b)), user)
		if err != nil {
			data["Error"] = "网关不可达"
		} else {
			var out map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&out)
			resp.Body.Close()
			if resp.StatusCode == 200 {
				data["Result"] = out
				if dev, _ := out["device_id"].(string); dev != "" && jkt != "" && out["status"] == "approved" {
					s.mu.Lock()
					if s.pins[user] == nil {
						s.pins[user] = map[string]string{}
					}
					s.pins[user][dev] = jkt // the gateway verified it matches the paired key
					s.mu.Unlock()
				}
			} else {
				e, _ := out["error"].(map[string]any)
				data["Error"] = e["message"]
			}
			if wantsJSON(r) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(resp.StatusCode)
				_ = json.NewEncoder(w).Encode(out)
				return
			}
		}
	}
	page.ExecuteTemplate(w, "link", data)
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request, user string) {
	id := r.FormValue("device_id")
	if r.Method != http.MethodPost || !strings.HasPrefix(id, "dev_") {
		http.Error(w, "bad request", 400)
		return
	}
	s.proxy("POST", "/lmbp/v1/tenant/devices/"+id+"/revoke")(w, r, user)
}

func (s *Server) home(w http.ResponseWriter, r *http.Request, user string) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	page.ExecuteTemplate(w, "home", map[string]string{"User": user, "Tenant": s.cfg.TenantID, "Public": s.cfg.PublicURL})
}

func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}

var page = template.Must(template.New("").Parse(`
{{define "head"}}<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Mock SaaS · 本机模型对话</title>
<style>
:root{--brand:#4d25d8;--brand-hover:#3f1db8;--brand-soft:#f2effe;--bg:#f8f9fb;--card:#fff;--bd:#e5e7eb;--txt:#111827;--mut:#6b7280;--ok:#059669;--err:#dc2626}
*{box-sizing:border-box}body{margin:0;font:14px/1.6 -apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei","Noto Sans CJK SC",sans-serif;color:var(--txt);background:var(--bg)}
header{height:56px;display:flex;align-items:center;gap:12px;padding:0 24px;background:#fff;border-bottom:1px solid var(--bd)}
header h1{font-size:15px;font-weight:600;margin:0}header .sp{flex:1}
a{color:var(--brand);text-decoration:none;font-weight:500}a:hover{text-decoration:underline}
input,textarea,select,button{font:inherit;padding:8px 12px;border:1px solid var(--bd);border-radius:8px;outline:none}
input:focus,textarea:focus,select:focus{border-color:var(--brand);box-shadow:0 0 0 3px rgba(77,37,216,.12)}
button{background:var(--brand);color:#fff;border-color:var(--brand);font-weight:500;cursor:pointer;transition:all .15s}
button:hover{background:var(--brand-hover)}button.sec{background:#fff;color:var(--txt);border-color:var(--bd)}button.sec:hover{background:#f3f4f6}
.wrap{max-width:1080px;margin:24px auto;padding:0 20px}
.auth-box{max-width:400px;margin:72px auto;background:var(--card);border:1px solid var(--bd);border-radius:16px;padding:28px;box-shadow:0 12px 32px rgba(15,23,42,.06)}
.card{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:18px;margin-bottom:16px;box-shadow:0 1px 2px rgba(15,23,42,.04)}
.card h3{margin:0 0 10px;font-size:14px}
.code{font-size:26px;letter-spacing:4px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;text-align:center}
.err{color:var(--err);background:#fef2f2;border:1px solid #fecaca;padding:8px 12px;border-radius:8px}
.ok{color:var(--ok);background:#ecfdf5;border:1px solid #a7f3d0;padding:8px 12px;border-radius:8px}
.workspace{display:grid;grid-template-columns:300px minmax(0,1fr);grid-template-rows:minmax(0,1fr);gap:16px;height:calc(100vh - 104px)}
.chat-panel{background:#fff;border:1px solid var(--bd);border-radius:14px;display:flex;flex-direction:column;min-height:0;overflow:hidden}
.chat-bar{flex-shrink:0;display:flex;align-items:center;gap:10px;padding:10px 16px;border-bottom:1px solid var(--bd)}
#chat{flex:1 1 0%;min-height:0;overflow-y:auto;padding:20px}
.turn{max-width:720px;margin:0 auto 16px;display:flex;flex-direction:column}
.turn.user{align-items:flex-end}.turn.assistant{align-items:flex-start}
.who{font-size:12px;color:var(--mut);margin-bottom:4px;font-weight:600}
.bubble{white-space:pre-wrap;word-break:break-word;padding:10px 15px;border-radius:16px;line-height:1.65;max-width:85%}
.turn.user .bubble{background:var(--brand);color:#fff;border-bottom-right-radius:4px}
.turn.assistant .bubble{background:var(--bg);border:1px solid var(--bd);border-top-left-radius:4px;width:100%;max-width:100%}
.composer{padding:12px 16px;border-top:1px solid var(--bd);background:#fafafa;display:flex;gap:10px;align-items:flex-end}
.composer textarea{flex:1;resize:none;background:#fff}
</style></head><body>{{end}}
{{define "login"}}{{template "head"}}<div class="auth-box"><h2 style="margin-top:0">登录 Mock SaaS</h2>{{if .Error}}<p class="err">{{.Error}}</p>{{end}}
<form method="post" action="/login"><input type="hidden" name="next" value="{{.Next}}"><p><input name="user" placeholder="用户名" style="width:100%"></p>
<p><input name="password" type="password" placeholder="密码" style="width:100%"></p><button style="width:100%">登录</button></form></div></body></html>{{end}}
{{define "link"}}{{template "head"}}<header><h1>Mock SaaS · 设备授权</h1><span class="sp"></span><span>当前用户：<b>{{.User}}</b></span><a href="/">返回对话</a></header>
<div class="auth-box" style="max-width:480px"><h3>连接本机设备</h3><p style="color:var(--mut)">在桌面连接器上会显示一个 8 位配对码（如 <span class="code" style="font-size:16px">BCDF-GHJK</span>），请在这里输入并确认。</p>
{{if .Result}}<p class="ok">已{{if eq (index .Result "status") "approved"}}连接{{else}}拒绝{{end}}设备（设备自报名称：{{index .Result "device_name"}}，设备 ID：{{index .Result "device_id"}}）</p>{{end}}
{{if .Error}}<p class="err">{{.Error}}</p>{{end}}
<form method="post" action="/link"><input type="hidden" name="jkt" value="{{.JKT}}"><p><input name="user_code" value="{{.Code}}" placeholder="XXXX-XXXX" class="code" style="width:100%" autocomplete="off"></p>
<div style="display:flex;gap:8px"><button style="flex:1">确认连接</button> <button name="deny" value="1" class="sec">拒绝</button></div></form></div></body></html>{{end}}
{{define "home"}}{{template "head"}}<header><h1>Mock SaaS · 本机模型对话</h1><span class="sp"></span><span><b>{{.User}}</b>（租户 {{.Tenant}}）</span><a href="/link">连接新设备</a><form style="display:inline" method="post" action="/logout"><button class="sec">退出</button></form></header>
<div class="wrap"><div class="workspace">
<div><div class="card"><h3>我的设备</h3><div id="devices">加载中…</div>
<p style="color:var(--mut);font-size:12.5px;margin-bottom:0">桌面连接器里填写服务地址 <code>{{.Public}}</code> 即可开始配对。</p></div></div>
<div class="chat-panel"><div class="chat-bar"><span style="font-weight:600;font-size:13px;color:var(--mut)">模型</span><select id="model"></select><span style="flex:1"></span><button class="sec" id="clear" type="button">清空对话</button></div>
<div id="chat"></div>
<div class="composer"><textarea id="prompt" rows="2" placeholder="输入消息，Enter 发送，Shift+Enter 换行">你好，请介绍一下你自己</textarea><button id="send">发送</button><button id="stop" class="sec" style="display:none">停止</button></div>
</div></div></div>
<script>
const chatEl=document.getElementById('chat');let history=[];
function addTurn(role,text){const t=document.createElement('div');t.className='turn '+role;const w=document.createElement('div');w.className='who';w.textContent=role==='user'?'我':'AI 助手';const b=document.createElement('div');b.className='bubble';b.textContent=text;t.append(w,b);chatEl.append(t);chatEl.scrollTop=chatEl.scrollHeight;return b;}
function node(tag,text,css){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(css)n.style.cssText=css;return n;}
// Device names and model ids are reported by the device: always plain text, never HTML.
async function load(){const d=await (await fetch('/api/devices')).json();const el=document.getElementById('devices');
el.replaceChildren(...(d.devices||[]).map(x=>{const r=node('div',undefined,'padding:6px 0;border-top:1px solid #f1f3f5');const b=node('b',x.name||'未命名设备');b.title='设备自报名称（由设备提供，仅供参考）';
r.append((x.online?'🟢':'⚪')+' ',b,node('br'),node('code',x.device_id,'font-size:11px;color:#6b7280'),' · '+(x.models||[]).join(', '));return r;}));if(!(d.devices||[]).length)el.textContent='还没有设备';
const m=await (await fetch('/api/models')).json();const sel=document.getElementById('model'),prev=sel.value;sel.replaceChildren(...(m.data||[]).map(x=>node('option',x.id)));if(prev)sel.value=prev;}
let ctl;const sendBtn=document.getElementById('send'),stopBtn=document.getElementById('stop'),promptEl=document.getElementById('prompt');
document.getElementById('clear').onclick=()=>{if(ctl)ctl.abort();history=[];chatEl.textContent='';};
promptEl.addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey&&!e.isComposing){e.preventDefault();sendBtn.click();}});
sendBtn.onclick=async()=>{const text=promptEl.value.trim(),model=document.getElementById('model').value;if(!text||!model)return;
promptEl.value='';addTurn('user',text);const msgs=history.concat([{role:'user',content:text}]);const out=addTurn('assistant','');
ctl=new AbortController();sendBtn.style.display='none';stopBtn.style.display='';let acc='';
try{const r=await fetch('/api/chat',{method:'POST',signal:ctl.signal,headers:{'Content-Type':'application/json'},body:JSON.stringify({model,stream:true,messages:msgs})});
if(!r.ok){out.textContent='错误: '+await r.text();return}const rd=r.body.getReader();const dec=new TextDecoder();let buf='';
for(;;){const {value,done}=await rd.read();if(done)break;buf+=dec.decode(value,{stream:true});let i;while((i=buf.indexOf('\n\n'))>=0){const ev=buf.slice(0,i);buf=buf.slice(i+2);
if(!ev.startsWith('data: '))continue;const p=ev.slice(6);if(p==='[DONE]')break;const j=JSON.parse(p);if(j.error){out.textContent+='\n[错误 '+j.error.code+'] '+j.error.message;break}
acc+=(j.choices[0].delta.content||'');out.textContent=acc;chatEl.scrollTop=chatEl.scrollHeight;}}
if(acc)history=msgs.concat([{role:'assistant',content:acc}]);}finally{sendBtn.style.display='';stopBtn.style.display='none';ctl=null;}};
stopBtn.onclick=()=>ctl&&ctl.abort();load();setInterval(load,5000);
</script></body></html>{{end}}`))
