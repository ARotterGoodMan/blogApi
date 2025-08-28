# -*- coding: utf-8 -*-
# @Date       : 2025-08-25
# @Time       : 2025/8/25:17:30
# @Author     : ARotterGoodMan
# @File       : test.py
# @ProjectName: BlogApi

import smtplib
from email.mime.text import MIMEText
from email.utils import formataddr
from config import SMTP_USER, SMTP_PASS, SMTP_PORT, SMTP_SERVER


# 邮件服务器配置

def send_reset_email(to_email, reset_link):
    subject = "密码重置请求"
    content = f"""
        <p>您好，</p>
        <p>您请求了重置密码，请点击下面的链接完成操作（1小时内有效）：</p>
        <p><a href="{reset_link}">{reset_link}</a></p>
        <p>如果这不是您的操作，请忽略此邮件。</p>
        """

    msg = MIMEText(content, "html", "utf-8")
    msg["From"] = formataddr(("Notes 应用", SMTP_USER))
    msg["To"] = to_email
    msg["Subject"] = subject

    try:
        server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT)
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, [to_email], msg.as_string())
        server.quit()
        print(f"✅ 重置邮件已发送到 {to_email}")
    except Exception as e:
        print(f"❌ 发送邮件失败: {e}")
