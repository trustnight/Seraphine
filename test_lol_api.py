import psutil
import requests
import base64
import urllib3
import time
import asyncio

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def create_lobby():
    """创建队伍请求"""
    client_info = get_lol_client_info()
    if not client_info:
        print("未找到LOL客户端或无法获取信息")
        return False
    
    # 构造请求URL和认证信息
    url = f"https://127.0.0.1:{client_info['port']}/lol-lobby/v2/lobby"
    auth = base64.b64encode(f"riot:{client_info['auth_token']}".encode()).decode()
    
    # 创建大乱斗队伍的配置
    data = {
        "queueId": 450  # 450是大乱斗模式的ID
    }
    
    try:
        response = requests.post(
            url,
            json=data,
            headers={
                'Authorization': f'Basic {auth}',
                'Content-Type': 'application/json'
            },
            verify=False
        )
        
        if response.status_code in [200, 204]:
            print("创建队伍成功！")
            return True
        else:
            print(f"创建队伍失败，状态码：{response.status_code}")
            print(f"错误信息：{response.text}")
            return False
            
    except Exception as e:
        print(f"请求发生错误：{e}")
        return False

def get_lol_client_info():
    """获取LOL客户端信息（端口和认证令牌）"""
    for process in psutil.process_iter():
        if process.name() == 'LeagueClientUx.exe':
            try:
                cmdline = process.cmdline()
                port = None
                auth_token = None
                
                # 从命令行参数中提取端口和认证令牌
                for cmd in cmdline:
                    if '--app-port=' in cmd:
                        port = cmd.split('=')[1]
                    elif '--remoting-auth-token=' in cmd:
                        auth_token = cmd.split('=')[1]
                    
                    if port and auth_token:
                        return {
                            'port': port,
                            'auth_token': auth_token,
                            'pid': process.pid
                        }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    return None

def start_matchmaking():
    """发送开始匹配请求"""
    # 获取客户端信息
    client_info = get_lol_client_info()
    if not client_info:
        print("未找到LOL客户端或无法获取信息")
        return False
    
    # 构造请求URL和认证信息
    url = f"https://127.0.0.1:{client_info['port']}/lol-lobby/v2/lobby/matchmaking/search"
    auth = base64.b64encode(f"riot:{client_info['auth_token']}".encode()).decode()
    
    try:
        # 发送POST请求
        response = requests.post(
            url,
            headers={'Authorization': f'Basic {auth}'},
            verify=False  # 忽略SSL验证
        )
        
        if response.status_code in [200, 204]:  # 添加204状态码的处理
            print("开始匹配成功！")
            return True
        else:
            print(f"开始匹配失败，状态码：{response.status_code}")
            print(f"错误信息：{response.text}")
            return False
            
    except Exception as e:
        print(f"请求发生错误：{e}")
        return False

def check_match_found():
    """检查是否找到对局"""
    client_info = get_lol_client_info()
    if not client_info:
        return False
    
    url = f"https://127.0.0.1:{client_info['port']}/lol-matchmaking/v1/ready-check"
    auth = base64.b64encode(f"riot:{client_info['auth_token']}".encode()).decode()
    
    try:
        response = requests.get(
            url,
            headers={'Authorization': f'Basic {auth}'},
            verify=False
        )
        
        if response.status_code == 200:
            data = response.json()
            return data.get('state') == 'InProgress'
        return False
    except:
        return False

def accept_match():
    """接受对局"""
    client_info = get_lol_client_info()
    if not client_info:
        return False
    
    url = f"https://127.0.0.1:{client_info['port']}/lol-matchmaking/v1/ready-check/accept"
    auth = base64.b64encode(f"riot:{client_info['auth_token']}".encode()).decode()
    
    try:
        response = requests.post(
            url,
            headers={'Authorization': f'Basic {auth}'},
            verify=False
        )
        return response.status_code in [200, 204]
    except:
        return False

def wait_for_match():
    """等待匹配并自动接受"""
    print("正在等待匹配...")
    while True:
        if check_match_found():
            print("找到对局！等待3秒后自动接受...")
            time.sleep(3)
            if accept_match():
                print("已自动接受对局！")
                return True
            else:
                print("接受对局失败！")
                return False
        time.sleep(1)  # 每秒检查一次

if __name__ == "__main__":
    try:
        client_info = get_lol_client_info()
        if client_info:
            print(f"找到LOL客户端：")
            print(f"PID: {client_info['pid']}")
            print(f"端口: {client_info['port']}")
            print(f"认证令牌: {client_info['auth_token']}")
            
            # 先创建队伍
            print("\n正在创建队伍...")
            if create_lobby():
                # 创建成功后开始匹配
                print("\n正在发送开始匹配请求...")
                q = input("是否匹配(y/n)：")
                if q.lower() == "y":
                    if start_matchmaking():
                        # 开始等待匹配
                        wait_for_match()
        else:
            print("未找到LOL客户端或无法获取信息")
    except Exception as e:
        print(f"发生错误: {e}")