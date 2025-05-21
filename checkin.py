import requests, base64, json, hashlib, os
from Crypto.Cipher import AES

def encrypt(key, text):
    cryptor = AES.new(key.encode('utf8'), AES.MODE_CBC, b'0102030405060708')
    length = 16
    count = len(text.encode('utf-8'))
    if (count % length != 0):
        add = length - (count % length)
    else:
        add = 16
    pad = chr(add)
    text1 = text + (pad * add)
    ciphertext = cryptor.encrypt(text1.encode('utf8'))
    cryptedStr = str(base64.b64encode(ciphertext), encoding='utf-8')
    return cryptedStr

def md5(s):
    hl = hashlib.md5()
    hl.update(s.encode(encoding='utf-8'))
    return hl.hexdigest()

def protect(text):
    return {
        "params": encrypt('TA3YiYCfY2dDJQgg', encrypt('0CoJUm6Qyw8W8jud', text)),
        "encSecKey": "84ca47bca10bad09a6b04c5c927ef077d9b9f1e37098aa3eac6ea70eb59df0aa28b691b7e75e4f1f9831754919ea784c8f74fbfadf2898b0be17849fd656060162857830e241aba44991601f137624094c114ea8d17bce815b0cd4e5b8e2fbaba978c6d1d14dc3d1faf852bdd28818031ccdaaa13a6018e1024e2aae98844210"
    }

s = requests.Session()
cookie_env = os.getenv("COOKIE")

# 登录逻辑
if cookie_env:
    print("检测到 COOKIE，尝试使用 Cookie 登录...")
    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Referer': 'http://music.163.com/',
        'Accept-Encoding': 'gzip, deflate',
        'Cookie': cookie_env
    }
    res = s.get("https://music.163.com", headers=headers)
    if res.status_code == 200:
        print("使用 Cookie 登录成功")
        s.headers.update(headers)
        tempcookie = s.cookies
    else:
        print("Cookie 登录失败，请检查 COOKIE 是否过期")
        exit(1)
else:
    print("未检测到 COOKIE，使用账号密码登录")
    phone = os.getenv("USER")
    password = os.getenv("PWD")
    if not phone or not password:
        print("缺少 USER 或 PWD，无法登录")
        exit(1)
    logindata = {
        "phone": phone,
        "countrycode": "86",
        "password": md5(password),
        "rememberLogin": "true"
    }
    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Referer': 'http://music.163.com/',
        'Accept-Encoding': 'gzip, deflate',
        "Cookie": "os=pc; appver=2.0.3.131777; channel=netease; __remember_me=true;"
    }
    res = s.post("https://music.163.com/weapi/login/cellphone", data=protect(json.dumps(logindata)), headers=headers)
    tempcookie = res.cookies
    object = json.loads(res.text)
    if object['code'] == 200:
        print("账号密码登录成功")
    else:
        print("登录失败！请检查密码是否正确！" + str(object['code']))
        exit(object['code'])

# 签到
res = s.post("https://music.163.com/weapi/point/dailyTask", data=protect('{"type":0}'))
object = json.loads(res.text)
if object['code'] == 200:
    print("签到成功，经验+" + str(object['point']))
elif object['code'] == -2:
    print("重复签到")
else:
    print("签到失败：" + object.get('msg', '未知错误'))

# 获取推荐歌单
csrf = requests.utils.dict_from_cookiejar(tempcookie).get('__csrf', '')
res = s.post("https://music.163.com/weapi/v1/discovery/recommend/resource", data=protect('{"csrf_token":"' + csrf + '"}'))
object = json.loads(res.text)
buffer = []
count = 0
for x in object['recommend']:
    url = 'https://music.163.com/weapi/v3/playlist/detail?csrf_token=' + csrf
    data = {
        'id': x['id'],
        'n': 1000,
        'csrf_token': csrf,
    }
    res = s.post(url, data=protect(json.dumps(data)))
    object = json.loads(res.text)
    for j in object['playlist']['trackIds']:
        buffer.append({
            "action": "play",
            "json": {
                "download": 0,
                "end": "playend",
                "id": j["id"],
                "sourceId": "",
                "time": "240",
                "type": "song",
                "wifi": 0
            }
        })
        count += 1
        if count >= 310:
            break
    if count >= 310:
        break

res = s.post("http://music.163.com/weapi/feedback/weblog", data=protect(json.dumps({"logs": json.dumps(buffer)})))
object = json.loads(res.text)
if object['code'] == 200:
    print("刷单成功！共" + str(count) + "首")
else:
    print("刷单失败：" + str(object['code']) + " " + object.get('message', '无错误信息'))
    exit(object['code'])
