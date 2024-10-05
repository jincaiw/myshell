
import requests
import logging
import time
import subprocess
import threading

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("website_monitor.log"),
        logging.StreamHandler()
    ]
)

# 要监控的网站列表
websites = [
    'http://example.com',
    'https://example.com',
    # 添加更多网站...
]

# 短信报警功能（需要您自行实现）
def send_sms_alert(message):
    # 在这里实现您的短信发送逻辑
    # 例如，使用Twilio API发送短信
    # 或者调用其他短信服务提供商的API
    logging.info("发送短信提醒: {}".format(message))
    pass

# 重启nginx服务
def restart_nginx():
    try:
        # 假设使用systemctl管理nginx服务
        subprocess.run(['sudo', 'systemctl', 'restart', 'nginx'], check=True)
        logging.info("nginx服务已重启")
    except subprocess.CalledProcessError as e:
        logging.error("重启nginx服务失败: {}".format(e))
        send_sms_alert("重启nginx服务失败: {}".format(e))

# 检查网站状态
def check_website(url):
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            logging.info("网站正常: {}".format(url))
            return True
        else:
            logging.warning("网站异常，状态码: {}，URL: {}".format(response.status_code, url))
            return False
    except requests.RequestException as e:
        logging.error("无法访问网站: {}，错误: {}".format(url, e))
        return False

# 主循环
def monitor_websites():
    while True:
        for url in websites:
            if not check_website(url):
                # 网站异常，重启nginx并发送短信报警
                logging.warning("检测到网站异常，尝试重启nginx并发送短信报警")
                restart_nginx()
                send_sms_alert("网站{}无法访问，已重启nginx服务".format(url))
        # 设置检查间隔，例如60秒
        time.sleep(60)

if __name__ == "__main__":
    monitor_thread = threading.Thread(target=monitor_websites)
    monitor_thread.start()


from twilio.rest import Client

def send_sms_alert(message):
    # Twilio账号SID和认证令牌
    account_sid = '您的Twilio账号SID'
    auth_token = '您的Twilio认证令牌'
    client = Client(account_sid, auth_token)

    message = client.messages.create(
        body=message,
        from_='您的Twilio电话号码',
        to='接收短信的电话号码'
    )
    logging.info("短信发送成功，SID: {}".format(message.sid))import os

from twilio.rest import Client
import logging

def send_sms_alert(message, to_number):
    # 从环境变量中获取Twilio账号SID和认证令牌
    account_sid = os.environ.get('TWILIO_ACCOUNT_SID')
    auth_token = os.environ.get('TWILIO_AUTH_TOKEN')

    if not account_sid or not auth_token:
        logging.error("Twilio账号SID或认证令牌未设置")
        return

    client = Client(account_sid, auth_token)

    if not validate_phone_number(to_number):
        logging.warning("接收短信的电话号码无效: {}".format(to_number))
        return

    message = client.messages.create(
        body=message,
        from_=os.environ.get('TWILIO_PHONE_NUMBER'),
        to=to_number
    )

    if message.sid:
        logging.info("短信发送成功，SID: {}".format(message.sid))
    else:
        logging.error("短信发送失败")

def validate_phone_number(number):
    # 在这里添加验证电话号码的逻辑，例如检查是否为有效的手机号码
    # 这里只是一个示例，您可以根据需要修改
    return number.startswith('+') and len(number) == 12

# 使用示例
send_sms_alert("这是一条测试短信", "+12345678901")

