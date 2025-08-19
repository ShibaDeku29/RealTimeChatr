// Tiny animated background (smooth, cheap)
const cvs = document.getElementById('bg');
const ctx = cvs.getContext('2d');
let w, h, t=0;
function resize(){ w = cvs.width = window.innerWidth; h = cvs.height = window.innerHeight; }
resize(); addEventListener('resize', resize);
function loop(){
  t += 0.003;
  const g = ctx.createLinearGradient(0,0,w,h);
  g.addColorStop(0, `hsl(${(t*120)%360}, 80%, 12%)`);
  g.addColorStop(1, `hsl(${(t*120+120)%360}, 80%, 8%)`);
  ctx.fillStyle = g; ctx.fillRect(0,0,w,h);
  requestAnimationFrame(loop);
}
loop();

// Helpers
const $ = s => document.querySelector(s);
const msg = $("#msg");
function setMsg(text, type=''){ msg.className = `msg ${type}`; msg.textContent = text; }
function validUsername(u){ return /^[a-zA-Z0-9_]{3,24}$/.test(u); }
function validPassword(p){ return typeof p === 'string' && p.length >= 6 && p.length <= 100; }

const username = $("#username");
const password = $("#password");
const btnLogin = $("#btnLogin");
const btnRegister = $("#btnRegister");
const togglePass = $("#togglePass");
const toChat = $("#toChat");

togglePass.addEventListener('click', ()=>{
  const t = password.getAttribute('type') === 'password' ? 'text' : 'password';
  password.setAttribute('type', t);
});

username.addEventListener('input', ()=>{
  if(username.value && !validUsername(username.value)) setMsg("Username: 3–24 ký tự, chỉ chữ/số/_", "err");
  else setMsg("");
});
password.addEventListener('input', ()=>{
  if(password.value && !validPassword(password.value)) setMsg("Mật khẩu tối thiểu 6 ký tự.", "err");
  else setMsg("");
});

async function call(path, body){
  const res = await fetch(path, {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify(body)
  });
  return res.json();
}
function startLoading(b){ b.classList.add('loading'); b.setAttribute('disabled',''); }
function stopLoading(b){ b.classList.remove('loading'); b.removeAttribute('disabled'); }

async function handleAuth(kind){
  const u = username.value.trim(), p = password.value;
  if(!validUsername(u)) return setMsg("Username không hợp lệ.", "err");
  if(!validPassword(p)) return setMsg("Mật khẩu quá ngắn.", "err");

  const btn = kind==='login' ? btnLogin : btnRegister;
  startLoading(btn); setMsg(kind==='login'?"Đang đăng nhập...":"Đang tạo tài khoản...");

  try{
    const data = await call(kind==='login'?"/auth/login":"/auth/register", {username:u, password:p});
    if(data && data.token){
      localStorage.setItem('chat_token', data.token);
      setMsg("Thành công! Đang chuyển vào phòng chat...", "ok");
      setTimeout(()=> location.href = "/index.html", 600);
    }else{
      setMsg(data?.error || "Có lỗi xảy ra.", "err");
    }
  }catch(e){
    setMsg("Không kết nối được máy chủ.", "err");
  }finally{
    stopLoading(btn);
  }
}

$("#authForm").addEventListener('submit', (e)=>{ e.preventDefault(); handleAuth('login'); });
btnRegister.addEventListener('click', ()=> handleAuth('register'));
toChat.addEventListener('click', (e)=>{
  e.preventDefault();
  const tk = localStorage.getItem('chat_token');
  if(tk){ location.href = "/index.html"; }
  else setMsg("Chưa có token — hãy đăng nhập/đăng ký trước nhé.", "err");
});
