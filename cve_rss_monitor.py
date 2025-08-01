#!/usr/bin/env python3
import os
import sys
import time
import json
import logging
import feedparser
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta, timezone
import schedule
import argparse

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("log/cve_monitor.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("CVE_Monitor")

# 创建必要的目录
os.makedirs("data", exist_ok=True)
os.makedirs("log", exist_ok=True)

class CVEMonitor:
    def __init__(self, rss_url, email_config=None):
        self.rss_url = rss_url
        self.email_config = email_config
        self.pull_count = 0
        # 加载上次运行状态
        self.load_state()

    def load_state(self):
        """加载上次运行状态"""
        try:
            with open("data/state.json", "r") as f:
                state = json.load(f)
                self.pull_count = state.get("pull_count", 0)
                logger.info(f"Loaded state: pull_count={self.pull_count}")
        except (FileNotFoundError, json.JSONDecodeError):
            logger.info("No valid state found, starting fresh")
            self.pull_count = 0

    def save_state(self):
        """保存当前运行状态"""
        state = {
            "pull_count": self.pull_count
        }
        with open("data/state.json", "w") as f:
            json.dump(state, f)
        logger.info(f"Saved state: pull_count={self.pull_count}")

    def fetch_rss_feed(self):
        """获取RSS源数据"""
        try:
            logger.info(f"Fetching RSS feed from {self.rss_url}")
            feed = feedparser.parse(self.rss_url)
            if feed.bozo:
                logger.error(f"Error parsing RSS feed: {feed.bozo_exception}")
                return None
            logger.info(f"Successfully fetched {len(feed.entries)} entries")
            return feed
        except Exception as e:
            logger.error(f"Failed to fetch RSS feed: {str(e)}")
            return None

    def generate_markdown(self, feed):
        """生成Markdown文件"""
        if not feed or not feed.entries:
            logger.warning("No entries to generate markdown")
            return None

        # 按照UTC时间命名文件
        utc_now = datetime.now(timezone.utc)
        date_str = utc_now.strftime("%Y-%m-%d")
        time_str = utc_now.strftime("%H%M%S")
        self.pull_count += 1
        filename = f"data/{date_str}-{time_str}-pull{self.pull_count}.md"

        # 写入Markdown内容
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"# CVE Vulnerability Report - {date_str} {time_str} UTC (Pull #{self.pull_count})\n\n")
            f.write(f"Source: {self.rss_url}\n\n")

            for entry in feed.entries:
                f.write(f"## {entry.get('title', 'Untitled')}\n")
                f.write(f"- **Link**: [{entry.get('link', 'No link')}]({entry.get('link', 'No link')})\n")
                f.write(f"- **Published**: {entry.get('published', 'Unknown')}\n")
                description = entry.get('description', 'No description')
                # 清理HTML标签
                import re
                clean_desc = re.sub('<[^<]+?>', '', description)
                f.write(f"- **Description**: {clean_desc}\n\n")

        logger.info(f"Generated markdown file: {filename}")
        self.save_state()
        return filename

    def send_email(self, report_files=None):
        """发送邮件"""
        if not self.email_config:
            logger.warning("Email configuration not provided, skipping email sending")
            return False

        try:
            # 创建邮件内容
            msg = MIMEMultipart()
            msg['From'] = self.email_config['from']
            msg['To'] = ', '.join(self.email_config['to'])
            msg['Subject'] = f"CVE Vulnerability Report - {datetime.now(timezone.utc).strftime('%Y-%m-%d')}"

            # 邮件正文
            body = "Daily CVE vulnerability report is attached.\n\n"
            if report_files:
                body += "Generated reports:\n"
                for file in report_files:
                    body += f"- {os.path.basename(file)}\n"
            msg.attach(MIMEText(body, 'plain'))

            # 附加报告文件
            if report_files:
                for file in report_files:
                    with open(file, 'rb') as f:
                        attachment = MIMEText(f.read(), 'base64', 'utf-8')
                        attachment['Content-Type'] = 'application/octet-stream'
                        attachment['Content-Disposition'] = f'attachment; filename={os.path.basename(file)}'
                        msg.attach(attachment)

            # 发送邮件
            if self.email_config['smtp_port'] == 465:
                # 使用SSL连接
                server = smtplib.SMTP_SSL(self.email_config['smtp_server'], self.email_config['smtp_port'])
            else:
                # 使用普通连接 + TLS
                server = smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port'])
                if self.email_config.get('use_tls', False):
                    server.starttls()
            if self.email_config.get('username') and self.email_config.get('password'):
                server.login(self.email_config['username'], self.email_config['password'])
            server.sendmail(self.email_config['from'], self.email_config['to'], msg.as_string())
            server.quit()

            logger.info(f"Email sent successfully to {', '.join(self.email_config['to'])}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email: {str(e)}")
            return False

    def run_rss_update(self):
        """运行RSS更新任务"""
        logger.info("Starting RSS update task")
        feed = self.fetch_rss_feed()
        if feed:
            markdown_file = self.generate_markdown(feed)
            return [markdown_file] if markdown_file else []
        return []

    def run_daily_email(self):
        """运行每日邮件任务"""
        logger.info("Starting daily email task")
        # 获取今天生成的所有报告
        today_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        report_files = [f for f in os.listdir("data") if f.startswith(today_utc) and f.endswith(".md")]
        report_files = [os.path.join("data", f) for f in report_files]
        self.send_email(report_files)

    def run_forever(self):
        """持续运行调度任务"""
        # 每15分钟更新一次RSS
        schedule.every(15).minutes.do(self.run_rss_update)

        # 每天UTC+8时间10点发送邮件
        # 转换为UTC时间（UTC+8 10点 = UTC 2点）
        schedule.every().day.at("02:00").do(self.run_daily_email)

        logger.info("Scheduler started. Running forever...")
        # 立即运行一次RSS更新
        self.run_rss_update()

        while True:
            schedule.run_pending()
            time.sleep(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='CVE RSS Monitor')
    parser.add_argument('--rss-url', default='https://cvefeed.io/rssfeed/severity/high.xml',
                        help='RSS feed URL (default: https://cvefeed.io/rssfeed/severity/high.xml)')
    parser.add_argument('--email-config', help='Path to email configuration JSON file')
    args = parser.parse_args()

    # 加载邮件配置
    email_config = None
    if args.email_config:
        try:
            with open(args.email_config, 'r') as f:
                email_config = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load email configuration: {str(e)}")

    # 创建并启动监控器
    monitor = CVEMonitor(args.rss_url, email_config)
    monitor.run_forever()