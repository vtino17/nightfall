import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


class EmailNotifier:
    def __init__(self, smtp_host, smtp_port, username, password, use_tls=True):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.use_tls = use_tls

    def send(self, to_addr, subject, body, from_addr=None, html=False):
        sender = from_addr or self.username
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = to_addr
        if html:
            msg.attach(MIMEText(body, "plain"))
            msg.attach(MIMEText(body, "html"))
        else:
            msg.attach(MIMEText(body, "plain"))
        try:
            server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=15)
            if self.use_tls:
                server.starttls()
            server.login(self.username, self.password)
            server.sendmail(sender, [to_addr], msg.as_string())
            server.quit()
            return True
        except (smtplib.SMTPException, OSError):
            return False

    def send_scan_report(self, to_addr, report_text, scan_name=None):
        subject = f"Nightfall Scan Report{' - ' + scan_name if scan_name else ''}"
        return self.send(to_addr, subject, report_text, html=False)


class EmailNotifierBuilder:
    @staticmethod
    def from_config(config):
        email_cfg = config.get("email", {})
        required = ["smtp_host", "smtp_port", "username", "password"]
        for key in required:
            if key not in email_cfg:
                raise ValueError(f"Email config missing: {key}")
        return EmailNotifier(
            smtp_host=email_cfg["smtp_host"],
            smtp_port=email_cfg["smtp_port"],
            username=email_cfg["username"],
            password=email_cfg["password"],
            use_tls=email_cfg.get("use_tls", True),
        )
