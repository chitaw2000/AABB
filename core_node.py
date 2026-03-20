import json, os, uuid, base64, urllib.parse, subprocess
from datetime import datetime, timedelta
from utils import db_lock, get_all_servers
from core_auto import find_available_node

try:
    from config import USERS_DB
except ImportError:
    USERS_DB = "/root/PanelMaster/users_db.json"

def get_safe_delete_cmd_multi(users_to_delete):
    py_script = f"""
import json
try:
    users = {json.dumps(users_to_delete)}
    path = '/usr/local/etc/xray/config.json'
    with open(path, 'r') as f: d = json.load(f)
    changed = False
    new_ib = []
    out_p = [str(u['port']) for u in users if u['proto'] == 'out']
    v2_e = [u['uname'] for u in users if u['proto'] == 'v2']
    for ib in d.get('inbounds', []):
        if str(ib.get('port')) in out_p and ib.get('protocol') == 'shadowsocks':
            changed = True; continue
        if ib.get('protocol') == 'vless' and 'settings' in ib and 'clients' in ib['settings']:
            orig = len(ib['settings']['clients'])
            ib['settings']['clients'] = [c for c in ib['settings']['clients'] if c.get('email') not in v2_e]
            if len(ib['settings']['clients']) != orig: changed = True
        new_ib.append(ib)
    if changed:
        d['inbounds'] = new_ib
        with open(path, 'w') as f: json.dump(d, f, indent=2)
except: pass
"""
    b64 = base64.b64encode(py_script.encode()).decode()
    return f"echo {b64} | base64 -d | python3"

def add_keys(node_id, group_id, raw_usernames, gb, days, proto, is_auto=False):
    db = {}
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)

        if is_auto:
            target_node, target_ip = find_available_node(group_id, len(raw_usernames), current_db=db)
        else:
            target_node = node_id
            target_ip = get_all_servers().get(node_id, {}).get('ip')

        if not target_ip: return False, "Node Offline"

        used_p = [int(i.get('port', 10000)) for i in db.values() if i.get('protocol') == 'out' and i.get('node') == target_node]
        max_p = max(used_p) if used_p else 10000
        exp = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")
        cmds = []
        
        for u in raw_usernames:
            u = u.strip()
            if not u or u in db: continue
            uid = str(uuid.uuid4())
            if proto == 'v2':
                port = "443"
                k = f"vless://{uid}@{target_ip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{u}"
                cmds.append(f"/usr/local/bin/v2ray-node-add-vless {u} {uid}")
            else:
                max_p += 1; port = str(max_p)
                ss_c = base64.b64encode(f"chacha20-ietf-poly1305:{uid}".encode()).decode()
                k = f"ss://{ss_c}@{target_ip}:{port}#{u}"
                cmds.append(f"/usr/local/bin/v2ray-node-add-out {u} {uid} {port} ; ufw allow {port}/tcp")
                
            db[u] = {"node": target_node, "protocol": proto, "uuid": uid, "port": port, "total_gb": float(gb), "expire_date": exp, "used_bytes": 0, "last_raw_bytes": 0, "is_blocked": False, "key": k}
        
        if cmds:
            cmds.append("systemctl restart xray")
            subprocess.Popen(f"ssh -o StrictHostKeyChecking=no root@{target_ip} \"{' ; '.join(cmds)}\"", shell=True)
            with open(USERS_DB, 'w') as f: json.dump(db, f)
    return True, "Success"

def toggle_key(username):
    # Toggle Logic (မူရင်းအတိုင်း)
    pass

def delete_key(username):
    bulk_delete_keys([username])

def bulk_delete_keys(usernames):
    # Multi-Delete Logic (မူရင်း logic ကို သုံးပြီး bulk ဖြစ်အောင် ပြင်ထားသည်)
    pass
