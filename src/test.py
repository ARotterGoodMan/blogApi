# -*- coding: utf-8 -*-
# @Date       : 2025-08-25
# @Time       : 2025/8/25:17:30
# @Author     : ARotterGoodMan
# @File       : test.py
# @ProjectName: BlogApi

import smtplib
from email.mime.text import MIMEText
from email.header import Header

# 邮件服务器配置
smtp_host = 'smtp.qq.com'  # poste.io 域名或IP
smtp_port = 587  # 587=Submission
smtp_user = 'shaoxiaoyao696@qq.com'
smtp_pass = 'jvsedefenlxjdjae'  # 邮箱密码或生成的应用密码

# 邮件内容
subject = '测试邮件'
body = '这是一封通过 poste.io 发送的测试邮件'

msg = MIMEText(body, 'plain', 'utf-8')
msg['Subject'] = Header(subject, 'utf-8')
msg['From'] = smtp_user
msg['To'] = '2195007463@qq.com'

# 连接 SMTP 服务器并发送邮件
try:
    server = smtplib.SMTP(smtp_host, smtp_port)
    server.starttls()  # 启用 TLS
    server.login(smtp_user, smtp_pass)
    server.sendmail(smtp_user, ['sxy@svipsvip.xn--fiqs8s'], msg.as_string())
    print("邮件发送成功")
except Exception as e:
    print("邮件发送失败:", e)
finally:
    server.quit()
