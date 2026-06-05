import asyncio
import json
import websockets
import sqlite3
import secrets
import base64
import hashlib
import os
from datetime import datetime

# Simple crypto
def gen_salt():
    return base64.b64encode(secrets.token_bytes(32)).decode()

def derive_key(pwd, salt):
    return hashlib.pbkdf2_hmac('sha256', pwd.encode(), salt.encode(), 100000, 32)

def encrypt(text, pwd, salt):
    key = derive_key(pwd, salt)
    tb = text.encode()
    enc = bytearray()
    for i in range(len(tb)):
        enc.append(tb[i] ^ key[i % len(key)])
    return base64.b64encode(secrets.token_bytes(8) + enc).decode()

def decrypt(enc, pwd, salt):
    key = derive_key(pwd, salt)
    data = base64.b64decode(enc)
    ct = data[8:]
    dec = bytearray()
    for i in range(len(ct)):
        dec.append(ct[i] ^ key[i % len(key)])
    return dec.decode()

# Database
def init_db():
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS msgs (id INTEGER PRIMARY KEY, ct TEXT, grp TEXT, sender TEXT, salt TEXT, ts TEXT)')
    c.execute('CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, status TEXT, grp TEXT, ts TEXT)')
    c.execute('CREATE TABLE IF NOT EXISTS groups (name TEXT PRIMARY KEY, salt TEXT, owner TEXT)')
    conn.commit()
    conn.close()
    print("DB ready")

def save_msg(ct, grp, sender, salt):
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    c.execute('INSERT INTO msgs (ct, grp, sender, salt, ts) VALUES (?,?,?,?,?)', (ct, grp, sender, salt, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_msgs(grp):
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    c.execute('SELECT ct, sender, salt FROM msgs WHERE grp=? ORDER BY id', (grp,))
    rows = c.fetchall()
    conn.close()
    return [{'ct': r[0], 'sender': r[1], 'salt': r[2]} for r in rows]

def set_status(name, status, grp):
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    c.execute('INSERT OR REPLACE INTO users (name, status, grp, ts) VALUES (?,?,?,?)', (name, status, grp, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_online(grp):
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    c.execute('SELECT name FROM users WHERE status="online" AND grp=?', (grp,))
    rows = c.fetchall()
    conn.close()
    return [r[0] for r in rows]

def get_grp_salt(grp):
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    c.execute('SELECT salt FROM groups WHERE name=?', (grp,))
    r = c.fetchone()
    conn.close()
    return r[0] if r else None

def create_grp(grp, salt, owner):
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    try:
        c.execute('INSERT INTO groups (name, salt, owner) VALUES (?,?,?)', (grp, salt, owner))
        conn.commit()
    except:
        pass
    conn.close()

init_db()

# HTML client
HTML = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ABAVANDIMWE</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box;}
        body{font-family:monospace;background:#0a0a0f;height:100vh;color:#0f0;}
        .login{position:fixed;top:0;left:0;right:0;bottom:0;display:flex;justify-content:center;align-items:center;background:#0a0a0f;z-index:1000;}
        .card{background:#050508;border:2px solid #0f0;border-radius:10px;padding:40px;width:90%;max-width:400px;}
        h1{text-align:center;margin-bottom:10px;}
        input{width:100%;padding:12px;margin:10px 0;background:#111;border:1px solid #0f0;border-radius:5px;color:#0f0;font-family:monospace;}
        button{width:100%;padding:12px;margin-top:20px;background:transparent;border:2px solid #0f0;border-radius:5px;color:#0f0;cursor:pointer;}
        button:hover{background:#0f0;color:#000;}
        .chat{display:none;width:100%;height:100%;flex-direction:column;}
        .chat.active{display:flex;}
        .header{padding:15px;background:#050508;border-bottom:1px solid #0f0;display:flex;justify-content:space-between;}
        .main{flex:1;display:flex;overflow:hidden;}
        .sidebar{width:250px;background:#050508;border-right:1px solid #0f0;}
        .sidebar h3{padding:15px;border-bottom:1px solid #0f0;}
        .users{padding:10px;}
        .user{padding:8px;margin:5px 0;border:1px solid #0f0;border-radius:5px;}
        .chatarea{flex:1;display:flex;flex-direction:column;}
        .msgs{flex:1;padding:20px;overflow-y:auto;}
        .msg{margin:10px 0;max-width:70%;}
        .msg.sent{margin-left:auto;text-align:right;}
        .bubble{background:#1a1a2e;border:1px solid #0f0;padding:8px 12px;border-radius:10px;display:inline-block;}
        .msg.sent .bubble{background:#0f0;color:#000;}
        .sender{font-size:10px;margin-bottom:4px;}
        .typing{padding:8px 20px;color:#0f0;font-style:italic;}
        .input{padding:15px;background:#050508;border-top:1px solid #0f0;display:flex;gap:10px;}
        .input input{flex:1;margin:0;}
        .input button{width:auto;margin:0;padding:12px 20px;}
    </style>
</head>
<body>
<div id="login" class="login">
    <div class="card">
        <h1># ABAVANDIMWE</h1>
        <p style="text-align:center;margin-bottom:20px;">by Mugisha Pc</p>
        <input type="text" id="username" placeholder="USERNAME">
        <input type="text" id="group" placeholder="GROUP">
        <input type="password" id="password" placeholder="PASSWORD">
        <button onclick="connect()">CONNECT</button>
        <p style="text-align:center;margin-top:20px;font-size:10px;">🔒 AES-256 | ⏰ Auto-Delete 24h</p>
    </div>
</div>
<div id="chat" class="chat">
    <div class="header"><h2 id="groupTitle"># LOADING</h2><span id="onlineCount">0 online</span></div>
    <div class="main">
        <div class="sidebar"><h3>● ONLINE</h3><div class="users" id="users">connecting...</div></div>
        <div class="chatarea"><div class="msgs" id="msgs"><div style="text-align:center;">connecting...</div></div><div class="typing" id="typing"></div><div class="input"><input type="text" id="msgInput" placeholder="Type message..."><button onclick="sendMsg()">SEND</button></div></div>
    </div>
</div>
<script>
let ws, username, group, password, salt, typingTimeout;

async function encrypt(t,p,s){
    let e=new TextEncoder(),km=await crypto.subtle.importKey('raw',e.encode(p),'PBKDF2',false,['deriveKey']);
    let k=await crypto.subtle.deriveKey({name:'PBKDF2',salt:e.encode(s),iterations:100000,hash:'SHA-256'},km,{name:'AES-GCM',length:256},false,['encrypt']);
    let iv=crypto.getRandomValues(new Uint8Array(12)),enc=await crypto.subtle.encrypt({name:'AES-GCM',iv},k,e.encode(t));
    let c=new Uint8Array(iv.length+enc.byteLength);c.set(iv,0);c.set(new Uint8Array(enc),iv.length);
    return btoa(String.fromCharCode(...c));
}

async function decrypt(c,p,s){
    let d=Uint8Array.from(atob(c),c=>c.charCodeAt(0)),iv=d.slice(0,12),data=d.slice(12),e=new TextEncoder();
    let km=await crypto.subtle.importKey('raw',e.encode(p),'PBKDF2',false,['deriveKey']);
    let k=await crypto.subtle.deriveKey({name:'PBKDF2',salt:e.encode(s),iterations:100000,hash:'SHA-256'},km,{name:'AES-GCM',length:256},false,['decrypt']);
    let dec=await crypto.subtle.decrypt({name:'AES-GCM',iv},k,data);
    return new TextDecoder().decode(dec);
}

function connect(){
    username=document.getElementById('username').value.trim();
    group=document.getElementById('group').value.trim();
    password=document.getElementById('password').value;
    if(!username||!group||!password){alert('Fill all fields');return;}
    let url=(location.protocol==='https:'?'wss://':'ws://')+location.host;
    ws=new WebSocket(url);
    ws.onopen=()=>ws.send(JSON.stringify({type:'join',username,group,password}));
    ws.onmessage=async(e)=>{
        let d=JSON.parse(e.data);
        if(d.type==='ready'){
            salt=d.salt;
            document.getElementById('login').style.display='none';
            document.getElementById('chat').classList.add('active');
            document.getElementById('groupTitle').innerText='# '+d.group;
        }else if(d.type==='message'||d.type==='history'){
            try{
                let dec=await decrypt(d.ciphertext,password,d.salt);
                addMsg(d.sender,dec,d.sender===username);
            }catch(e){addMsg(d.sender,'🔒 ENCRYPTED',d.sender===username);}
        }else if(d.type==='users'){
            document.getElementById('onlineCount').innerText=d.users.length+' online';
            let ud=document.getElementById('users');
            if(d.users.length===0)ud.innerHTML='<div class="user">no users</div>';
            else ud.innerHTML=d.users.map(u=>'<div class="user">● '+escapeHtml(u)+'</div>').join('');
        }else if(d.type==='typing'){
            document.getElementById('typing').innerHTML='✏️ '+d.user+' is typing...';
        }else if(d.type==='stop_typing'){
            document.getElementById('typing').innerHTML='';
        }
    };
    ws.onerror=()=>alert('Connection failed');
}

function addMsg(sender,text,isSent){
    let m=document.getElementById('msgs');
    if(m.children.length===1&&m.children[0].innerText.includes('connecting'))m.innerHTML='';
    let div=document.createElement('div');
    div.className='msg '+(isSent?'sent':'received');
    div.innerHTML='<div class="sender">'+(isSent?'YOU':sender)+'</div><div class="bubble">'+escapeHtml(text)+'</div>';
    m.appendChild(div);
    m.scrollTop=m.scrollHeight;
}

function escapeHtml(t){let d=document.createElement('div');d.textContent=t;return d.innerHTML;}

document.getElementById('msgInput')?.addEventListener('input',function(){
    if(ws&&ws.readyState===WebSocket.OPEN){
        ws.send(JSON.stringify({type:'typing'}));
        clearTimeout(typingTimeout);
        typingTimeout=setTimeout(()=>ws.send(JSON.stringify({type:'stop_typing'})),1000);
    }
});

document.getElementById('msgInput')?.addEventListener('keypress',function(e){if(e.key==='Enter')sendMsg();});

async function sendMsg(){
    let i=document.getElementById('msgInput'),t=i.value.trim();
    if(!t||!ws||ws.readyState!==WebSocket.OPEN)return;
    try{
        let c=await encrypt(t,password,salt);
        ws.send(JSON.stringify({type:'message',ciphertext:c,salt:salt}));
        i.value='';
    }catch(e){}
}
</script>
</body>
</html>'''

# WebSocket connections
conns = {}

async def ws_handler(ws, path):
    user = None
    grp = None
    try:
        async for msg in ws:
            data = json.loads(msg)
            t = data.get('type')
            if t == 'join':
                user = data['username']
                grp = data['group']
                pwd = data['password']
                salt = get_grp_salt(grp)
                if not salt:
                    salt = gen_salt()
                    create_grp(grp, salt, user)
                if grp not in conns:
                    conns[grp] = {}
                conns[grp][user] = ws
                set_status(user, 'online', grp)
                for m in get_msgs(grp):
                    await ws.send(json.dumps({'type': 'history', 'ciphertext': m['ct'], 'sender': m['sender'], 'salt': m['salt']}))
                online = get_online(grp)
                if grp in conns:
                    for u, w in conns[grp].items():
                        try:
                            await w.send(json.dumps({'type': 'users', 'users': online}))
                        except:
                            pass
                await ws.send(json.dumps({'type': 'ready', 'salt': salt, 'group': grp}))
                print(f"+ {user} joined {grp}")
            elif t == 'message':
                ct = data['ciphertext']
                salt = data['salt']
                save_msg(ct, grp, user, salt)
                if grp in conns:
                    for u, w in conns[grp].items():
                        if u != user:
                            try:
                                await w.send(json.dumps({'type': 'message', 'ciphertext': ct, 'sender': user, 'salt': salt}))
                            except:
                                pass
            elif t == 'typing':
                if grp in conns:
                    for u, w in conns[grp].items():
                        if u != user:
                            try:
                                await w.send(json.dumps({'type': 'typing', 'user': user}))
                            except:
                                pass
            elif t == 'stop_typing':
                if grp in conns:
                    for u, w in conns[grp].items():
                        if u != user:
                            try:
                                await w.send(json.dumps({'type': 'stop_typing', 'user': user}))
                            except:
                                pass
    except:
        pass
    finally:
        if user and grp:
            if grp in conns and user in conns[grp]:
                del conns[grp][user]
            set_status(user, 'offline', grp)
            online = get_online(grp)
            if grp in conns:
                for u, w in conns[grp].items():
                    try:
                        await w.send(json.dumps({'type': 'users', 'users': online}))
                    except:
                        pass
            print(f"- {user} left {grp}")

# HTTP handler
async def http_handler(reader, writer):
    try:
        data = await reader.read(1024)
        if data:
            req = data.decode().split(' ')[0] if data else ''
            if req == 'GET':
                resp = f'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {len(HTML)}\r\nConnection: close\r\n\r\n{HTML}'
                writer.write(resp.encode())
                await writer.drain()
        writer.close()
        await writer.wait_closed()
    except:
        pass

# Main
PORT = int(os.getenv('PORT', 8080))

print("""
╔════════════════════════════════════════╗
║     ABAVANDIMWE - Secure Messaging    ║
║        Messages Auto-Delete 24h       ║
║          Author: Mugisha Pc           ║
╚════════════════════════════════════════╝
""")
print(f"Starting on port {PORT}")

async def main():
    ws_server = await websockets.serve(ws_handler, '0.0.0.0', PORT)
    http_server = await asyncio.start_server(http_handler, '0.0.0.0', PORT)
    print(f"Server running on port {PORT}")
    await asyncio.gather(ws_server.wait_closed(), http_server.wait_closed())

asyncio.run(main())
