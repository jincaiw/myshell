# sms_alert.py

# 导入Twilio客户端库
from twilio.rest import Client
import os

# 从环境变量中读取Twilio的配置信息
account_sid = os.environ['TWILIO_ACCOUNT_SID']
auth_token = os.environ['TWILIO_AUTH_TOKEN']
client = Client(account_sid, auth_token)

# 发送短信的函数
def send_sms(to_number, message):
    """
    向指定的电话号码发送短信。
    
    参数:
    - to_number (str): 接收短信的电话号码。
    - message (str): 要发送的消息内容。
    """
    try:
        # 使用Twilio提供的号码发送短信
        message = client.messages.create(
            body=message,
            from_='<your_twilio_phone_number>',  # 替换为你的Twilio号码
            to=to_number
        )
        print(f"SMS sent successfully to {to_number}")
    except Exception as e:
        print(f"Failed to send SMS: {e}")

# 拨打电话的函数
def make_call(to_number, url):
    """
    向指定的电话号码拨打电话。
    
    参数:
    - to_number (str): 接听电话的电话号码。
    - url (str): TwiML应用程序的URL，用于处理电话。
    """
    try:
        # 使用Twilio提供的号码拨打电话
        call = client.calls.create(
            to=to_number,
            from_='<your_twilio_phone_number>',  # 替换为你的Twilio号码
            url=url
        )
        print(f"Call initiated to {to_number}")
    except Exception as e:
        print(f"Failed to make call: {e}")



# 调用方式
"""
# main.py

import os
from notifications import send_sms, make_call

# 设置环境变量
os.environ['TWILIO_ACCOUNT_SID'] = 'your_account_sid'
os.environ['TWILIO_AUTH_TOKEN'] = 'your_auth_token'

# 示例调用
send_sms('+1234567890', 'Hello, this is a test message.')
make_call('+1234567890', 'http://demo.twilio.com/docs/voice.xml')
"""