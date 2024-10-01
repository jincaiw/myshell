import socket
import smtplib
from email.mime.text import MIMEText
 
def send_mail(body):
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login('youremail@gmail.com', 'password')
    message = MIMEText(body)
    message['Subject'] = 'Service Alert'
    message['From'] = 'youremail@gmail.com'
    message['To'] = 'admin@example.com'
    server.sendmail('youremail@gmail.com', ['admin@example.com'], message.as_string())
    server.quit()
 
while True:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('www.baidu.com', 80))
 
    if result != 0:
        send_mail('Service is down')
 
    sock.close()