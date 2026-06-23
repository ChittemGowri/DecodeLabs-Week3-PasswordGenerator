import streamlit as st
import plotly.graph_objects as go
import secrets, string, math, json, os, requests
from datetime import datetime

st.set_page_config(page_title="VaultForge AI", page_icon="🔐", layout="wide")

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
HISTORY_FILE = os.path.join(BASE_DIR, "history.json")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=JetBrains+Mono:wght@400;600;700&display=swap');
html,body,[class*="css"]{font-family:'Inter',sans-serif;}

/* Clean Light Background */
.stApp{background:#f8fafc;color:#0f172a;}

/* Premium Indigo/Tech Header */
.hdr{background:linear-gradient(135deg, #312e81, #4338ca); border:none; 
     box-shadow: 0 10px 25px -5px rgba(67, 56, 202, 0.3);
     border-radius:14px;padding:1.5rem 2rem;margin-bottom:1.2rem;position:relative;overflow:hidden;}
.hdr::before{content:'';position:absolute;top:0;left:0;right:0;height:4px;
              background:linear-gradient(90deg, #06b6d4, #3b82f6);}
.hdr h1{font-size:1.8rem;font-weight:700;color:#ffffff;margin:0;}
.hdr p{color:#e0e7ff;margin:.2rem 0 0;font-size:.85rem;font-weight:500;}

/* Crisp Password Box */
.pw-box{background:#ffffff;border:2px solid #818cf8;border-radius:12px;
        padding:1.2rem 1.5rem;margin:1rem 0;font-family:'JetBrains Mono',monospace;
        font-size:1.25rem;font-weight:700;letter-spacing:.04em;color:#1e1b4b;
        word-break:break-all;box-shadow:0 4px 6px -1px rgba(0,0,0,0.05);}
.pw-label{font-size:.62rem;text-transform:uppercase;letter-spacing:.1em;
          color:#4f46e5;font-family:'Inter',sans-serif;margin-bottom:.4rem;display:block;font-weight:700;}

/* Soft Pastel Tech AI Box */
.ai-box{background:linear-gradient(135deg,#f0f9ff,#e0f2fe);border:1px solid #bae6fd;
         border-radius:12px;padding:1rem 1.25rem;margin-top:.8rem;box-shadow: 0 2px 4px rgba(0,0,0,0.02);}
.ai-label{font-size:.65rem;text-transform:uppercase;letter-spacing:.1em;
           color:#0369a1;margin-bottom:.4rem;font-weight:700;}

/* Neumorphic History Rows */
.hist-row{background:#ffffff;border:1px solid #e2e8f0;border-radius:8px;
          padding:.7rem 1rem;margin-bottom:.5rem;font-family:'JetBrains Mono',monospace;
          font-size:.85rem;color:#334155;box-shadow:0 1px 2px rgba(0,0,0,0.04);}

/* Light Mode Inputs Styling */
.stTextInput>div>div>input,.stNumberInput>div>div>input{
  background:#ffffff!important;border:1px solid #cbd5e1!important;
  color:#0f172a!important;border-radius:7px!important;}
</style>
""", unsafe_allow_html=True)

LOWER  = string.ascii_lowercase
UPPER  = string.ascii_uppercase
DIGITS = string.digits
SYMS   = string.punctuation
AMBIG  = set("0O1lI|")
KB_WALKS = ["qwerty","asdfgh","zxcvbn","qazwsx","123456","abcdef"]
WORDLIST = [
    "apple","brave","cloud","delta","eagle","flame","globe","honey","ivory","jewel",
    "karma","lemon","maple","noble","ocean","pearl","queen","river","stone","tiger",
    "ultra","vivid","water","xenon","yacht","zebra","amber","blaze","cedar","dusk",
    "ember","frost","grace","halo","indie","jade","knack","lunar","mango","nexus",
    "orbit","pixel","quest","radar","solar","terra","unity","vault","waltz","xray",
    "yield","zesty","anchor","bridge","cipher","drift","ether","flint","glyph","haven",
    "index","joust","kinetic","loft","magnet","nerve","onyx","prism","quartz","relay",
    "sigma","twist","umbra","vigor","whirl","xylem","young","zenith","agate","bliss",
]

def build_pool(lo=True,up=True,dg=True,sy=True,na=False):
    p = (LOWER if lo else "")+(UPPER if up else "")+(DIGITS if dg else "")+(SYMS if sy else "")
    return "".join(c for c in p if c not in AMBIG) if na else p

def gen_pw(n,lo=True,up=True,dg=True,sy=True,na=False):
    pool = build_pool(lo,up,dg,sy,na)
    if not pool: raise ValueError("Select at least one character class.")
    g = []
    if lo: g.append(secrets.choice([c for c in LOWER if c not in (AMBIG if na else set())]))
    if up: g.append(secrets.choice([c for c in UPPER if c not in (AMBIG if na else set())]))
    if dg: g.append(secrets.choice([c for c in DIGITS if c not in (AMBIG if na else set())]))
    if sy: g.append(secrets.choice(SYMS))
    g = g[:n]; fill = [secrets.choice(pool) for _ in range(n-len(g))]
    combined = g+fill; secrets.SystemRandom().shuffle(combined)
    return "".join(combined)

def gen_phrase(words=4,sep="-",cap=True,digit=True):
    w = [secrets.choice(WORDLIST) for _ in range(words)]
    if cap: w = [x.capitalize() for x in w]
    p = sep.join(w)
    if digit: p += sep+str(secrets.randbelow(100))
    return p

def entropy(n, pool): return n*math.log2(pool) if pool>0 and n>0 else 0.0

def strength(e):
    if e<28:  return "Very Weak",   "#ef4444", 10
    if e<40:  return "Weak",        "#f97316", 25
    if e<60:  return "Moderate",    "#eab308", 50
    if e<100: return "Strong",      "#22c55e", 78
    return          "Very Strong", "#10b981", 100

def crack(e):
    s = (2**e)/1e10
    if s<1:     return "< 1 sec 🔴"
    if s<60:    return f"{s:.0f}s 🔴"
    if s<3600:  return f"{s/60:.0f}min 🔴"
    if s<86400: return f"{s/3600:.1f}hr 🟡"
    if s<3.15e7:return f"{s/86400:.0f}days 🟡"
    if s<3.15e9:return f"{s/3.15e7:.0f}yrs 🟢"
    return f"{s/3.15e9:.1e} centuries 🟢"

def patterns(pw):
    w=[]; p=pw.lower()
    for k in KB_WALKS:
        if k in p: w.append(f"Keyboard walk: '{k}'")
    if len(set(pw))<len(pw)*0.5: w.append("Too many repeated chars")
    if p in [x.lower() for x in WORDLIST]: w.append("Single dictionary word")
    return w

def policy(pw):
    return [("Min 8 chars",len(pw)>=8),("Min 12 chars",len(pw)>=12),("Min 16 chars",len(pw)>=16),
            ("Has lowercase",any(c in LOWER for c in pw)),("Has uppercase",any(c in UPPER for c in pw)),
            ("Has digit",any(c in DIGITS for c in pw)),("Has symbol",any(c in SYMS for c in pw)),
            ("No keyboard walk",not any(k in pw.lower() for k in KB_WALKS)),
            ("Not dictionary word",pw.lower() not in [x.lower() for x in WORDLIST])]

def load_hist():
    if not os.path.exists(HISTORY_FILE): return []
    try:
        with open(HISTORY_FILE) as f: return json.load(f)
    except Exception: return []

def save_hist(r):
    h=load_hist(); h.append(r)
    with open(HISTORY_FILE,"w") as f: json.dump(h[-30:],f,indent=2)

def nvidia(api_key,prompt,system="Be concise.",max_tokens=400):
    try:
        r=requests.post("https://integrate.api.nvidia.com/v1/chat/completions",
            headers={"Authorization":f"Bearer {api_key}","Content-Type":"application/json"},
            json={"model":"meta/llama-3.1-8b-instruct",
                  "messages":[{"role":"system","content":system},{"role":"user","content":prompt}],
                  "temperature":0.4,"max_tokens":max_tokens},timeout=25)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"].strip()
    except requests.exceptions.Timeout: return "⚠️ Timeout."
    except Exception as e: return f"⚠️ {e}"

if "pw" not in st.session_state: st.session_state.pw=""
if "phrase" not in st.session_state: st.session_state.phrase=""
if "batch" not in st.session_state: st.session_state.batch=[]

st.markdown("""
<div class="hdr">
  <h1>🔐 VaultForge AI</h1>
  <p>DecodeLabs Internship 2026 · Chittem Gowri Sankar · NVIDIA NIM</p>
</div>""",unsafe_allow_html=True)

with st.sidebar:
    api_key = st.text_input("🔑 NVIDIA API Key",type="password",placeholder="nvapi-...")
    st.caption("[Get key →](https://build.nvidia.com)")
    st.divider()
    length = st.slider("Length",8,128,20)
    lo=st.checkbox("Lowercase",True); up=st.checkbox("Uppercase",True)
    dg=st.checkbox("Digits",True);   sy=st.checkbox("Symbols",False)
    na=st.checkbox("Exclude ambiguous",False)
    pool=build_pool(lo,up,dg,sy,na); ent=entropy(length,len(pool))
    nm,col,pct=strength(ent)
    st.divider()
    st.markdown(f"**Entropy:** `{ent:.1f} bits`")
    st.markdown(f"**Strength:** <span style='color:{col};font-weight:700'>{nm}</span>",unsafe_allow_html=True)
    st.markdown(f"""<div style="background:#e2e8f0;border-radius:5px;height:9px;overflow:hidden;margin:6px 0">
        <div style="width:{pct}%;height:100%;background:{col};border-radius:5px"></div></div>""",unsafe_allow_html=True)
    st.markdown(f"**Crack:** `{crack(ent)}`")

t1,t2,t3,t4,t5,t6=st.tabs(["🔑 Generate","💬 Passphrase","🔍 Analyze","📋 Batch","🤖 AI","📜 History"])

with t1:
    st.subheader("Generate Password")
    if st.button("⚡ Generate",type="primary",use_container_width=True):
        if not any([lo,up,dg,sy]): st.error("Select at least one character class.")
        else:
            pw=gen_pw(length,lo,up,dg,sy,na); st.session_state.pw=pw
            save_hist({"type":"password","length":length,"entropy":round(ent,1),"strength":nm,"date":datetime.now().strftime("%Y-%m-%d %H:%M")})
    if st.session_state.pw:
        pw=st.session_state.pw
        st.markdown(f'<div class="pw-box"><span class="pw-label">🔐 GENERATED</span>{pw}</div>',unsafe_allow_html=True)
        st.code(pw,language=None)
        st.caption("⬆️ Click copy icon to copy")
        c1,c2,c3=st.columns(3)
        c1.metric("Length",f"{len(pw)}"); c2.metric("Entropy",f"{ent:.1f} bits"); c3.metric("Strength",nm)
        st.markdown(f"**Crack time:** `{crack(ent)}`")
        st.markdown(f"""<div style="background:#e2e8f0;border-radius:5px;height:10px;overflow:hidden;margin:8px 0">
            <div style="width:{pct}%;height:100%;background:{strength(ent)[1]};border-radius:5px"></div></div>""",unsafe_allow_html=True)
        for w in patterns(pw): st.warning(f"⚠️ {w}")
        if api_key and st.button("🤖 AI Policy Review"):
            chk=policy(pw); fails=[r for r,p in chk if not p]
            with st.spinner():
                r=nvidia(api_key,f"PW entropy={ent:.1f}bits, crack={crack(ent)}, failed: {fails or 'none'}. Give 3 specific tips. Under 90 words.","You are a cybersecurity expert. Be concise.")
            st.markdown(f'<div class="ai-box"><div class="ai-label">🤖 Policy Review</div><div style="color:#0f172a;white-space:pre-wrap">{r}</div></div>',unsafe_allow_html=True)

with t2:
    st.subheader("Diceware Passphrase")
    c1,c2=st.columns(2)
    wc=c1.slider("Words",3,8,4); sep=c1.text_input("Separator","-")
    cap=c2.checkbox("Capitalize",True); dgt=c2.checkbox("Append number",True)
    pp_ent=wc*math.log2(len(WORDLIST))+(math.log2(100) if dgt else 0)
    pn,pc,pp=strength(pp_ent)
    st.markdown(f"**Entropy: `{pp_ent:.1f} bits`** — {pn} · `{crack(pp_ent)}`")
    if st.button("⚡ Generate Passphrase",type="primary",use_container_width=True):
        ph=gen_phrase(wc,sep or "-",cap,dgt); st.session_state.phrase=ph
        save_hist({"type":"passphrase","words":wc,"entropy":round(pp_ent,1),"strength":pn,"date":datetime.now().strftime("%Y-%m-%d %H:%M")})
    if st.session_state.phrase:
        st.markdown(f'<div class="pw-box"><span class="pw-label">💬 PASSPHRASE</span>{st.session_state.phrase}</div>',unsafe_allow_html=True)
        st.code(st.session_state.phrase,language=None)
        st.info("💡 Passphrases are easier to memorize and equally secure due to high entropy.")

with t3:
    st.subheader("Analyze a Password")
    test=st.text_input("Enter password",type="password",placeholder="Paste or type a password…")
    if test:
        ps=(26 if any(c in LOWER for c in test) else 0)+(26 if any(c in UPPER for c in test) else 0)+(10 if any(c in DIGITS for c in test) else 0)+(32 if any(c in SYMS for c in test) else 0)
        ps=max(ps,len(set(test)),10); ev=entropy(len(test),ps); en,ec,ep=strength(ev)
        c1,c2,c3,c4=st.columns(4)
        c1.metric("Length",len(test)); c2.metric("Pool",ps); c3.metric("Entropy",f"{ev:.1f}"); c4.metric("Strength",en)
        st.markdown(f"""<div style="background:#e2e8f0;border-radius:5px;height:10px;overflow:hidden;margin:8px 0">
            <div style="width:{ep}%;height:100%;background:{ec};border-radius:5px"></div></div>""",unsafe_allow_html=True)
        st.markdown(f"**Crack time:** `{crack(ev)}`")
        chk=policy(test)
        for rule,passed in chk: st.markdown(f"{'✅' if passed else '❌'} {rule}")
        passed_c=sum(1 for _,p in chk if p)
        st.markdown(f"**Score: {passed_c}/{len(chk)}**")
        for w in patterns(test): st.warning(f"⚠️ {w}")
        if api_key and st.button("🤖
