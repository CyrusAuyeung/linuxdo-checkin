"""
cron: 0 */6 * * *
new Env("Linux.Do 签到")
"""

import os
import random
import time
import functools
import sys
import re
from loguru import logger
from DrissionPage import ChromiumOptions, Chromium
from tabulate import tabulate
from curl_cffi import requests
from bs4 import BeautifulSoup


def retry_decorator(retries=3, min_delay=5, max_delay=10):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == retries - 1:
                        logger.error(f"函数 {func.__name__} 最终执行失败: {str(e)}")
                    logger.warning(
                        f"函数 {func.__name__} 第 {attempt + 1}/{retries} 次尝试失败: {str(e)}"
                    )
                    if attempt < retries - 1:
                        sleep_s = random.uniform(min_delay, max_delay)
                        logger.info(
                            f"将在 {sleep_s:.2f}s 后重试 ({min_delay}-{max_delay}s 随机延迟)"
                        )
                        time.sleep(sleep_s)
            return None

        return wrapper

    return decorator


os.environ.pop("DISPLAY", None)
os.environ.pop("DYLD_LIBRARY_PATH", None)

# --- 环境变量读取 ---
USERNAME = os.environ.get("LINUXDO_USERNAME")
PASSWORD = os.environ.get("LINUXDO_PASSWORD")
COOKIE_STR = os.environ.get("LINUXDO_COOKIE")

BROWSE_ENABLED = os.environ.get("BROWSE_ENABLED", "true").strip().lower() not in [
    "false",
    "0",
    "off",
]
if not USERNAME:
    USERNAME = os.environ.get("USERNAME")
if not PASSWORD:
    PASSWORD = os.environ.get("PASSWORD")
    
# 通知相关变量
GOTIFY_URL = os.environ.get("GOTIFY_URL")
GOTIFY_TOKEN = os.environ.get("GOTIFY_TOKEN")
SC3_PUSH_KEY = os.environ.get("SC3_PUSH_KEY")
# WxPusher 变量
WXPUSH_TOKEN = os.environ.get("WXPUSH_TOKEN")
WXPUSH_UID = os.environ.get("WXPUSH_UID")  # 新增 UID 读取


HOME_URL = "https://linux.do/"
LOGIN_URL = "https://linux.do/login"
SESSION_URL = "https://linux.do/session"
CSRF_URL = "https://linux.do/session/csrf"


class LinuxDoBrowser:
    def __init__(self) -> None:
        from sys import platform

        if platform == "linux" or platform == "linux2":
            platformIdentifier = "X11; Linux x86_64"
        elif platform == "darwin":
            platformIdentifier = "Macintosh; Intel Mac OS X 10_15_7"
        elif platform == "win32":
            platformIdentifier = "Windows NT 10.0; Win64; x64"
        else:
            platformIdentifier = "X11; Linux x86_64"

        co = (
            ChromiumOptions()
            .headless(True)
            .incognito(True)
            .set_argument("--no-sandbox")
        )
        co.set_user_agent(
            f"Mozilla/5.0 ({platformIdentifier}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
        )
        self.browser = Chromium(co)
        self.page = self.browser.new_tab()
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0",
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Accept-Language": "zh-CN,zh;q=0.9",
            }
        )

    def check_login_success(self):
        """辅助函数：检查页面是否包含登录后的元素"""
        try:
            user_ele = self.page.ele("@id=current-user")
            if user_ele:
                logger.success("✅ 登录验证成功 (找到 current-user)")
                return True
            
            if "avatar" in self.page.html:
                logger.success("✅ 登录验证成功 (找到 avatar)")
                return True
                
        except Exception:
            pass
        return False

    def login(self):
        logger.info("开始登录流程...")

        # ---------------------------------------------------------------------
        # 方案 A: Cookie 登录
        # ---------------------------------------------------------------------
        if COOKIE_STR:
            logger.info("检测到 LINUXDO_COOKIE 配置，尝试通过 Cookie 免密登录...")
            try:
                dp_cookies = []
                for item in COOKIE_STR.split(';'):
                    if '=' in item:
                        key, value = item.strip().split('=', 1)
                        dp_cookies.append({
                            "name": key, 
                            "value": value, 
                            "domain": ".linux.do", 
                            "path": "/"
                        })

                self.page.set.cookies(dp_cookies)

                headers = {"Cookie": COOKIE_STR}
                self.session.headers.update(headers)

                logger.info("Cookie 设置完毕，正在前往主页验证...")
                self.page.get(HOME_URL)
                time.sleep(3)

                if self.check_login_success():
                    return True
                else:
                    logger.warning("Cookie 登录失效，尝试回退到账号密码登录...")
            except Exception as e:
                logger.error(f"Cookie 登录过程出错: {e}")
                logger.info("尝试回退到账号密码登录...")

        # ---------------------------------------------------------------------
        # 方案 B: 账号密码登录
        # ---------------------------------------------------------------------
        if not USERNAME or not PASSWORD:
            logger.error("未配置账号密码，无法继续。")
            return False

        logger.info("尝试使用账号密码登录...")
        
        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Referer": LOGIN_URL,
        }
        
        try:
            resp_csrf = self.session.get(CSRF_URL, headers=headers, impersonate="chrome136")
            
            if resp_csrf.status_code == 403 or "<html" in resp_csrf.text[:100].lower():
                logger.error("❌ 获取 CSRF 失败: GitHub IP 被 Cloudflare 拦截。请配置 LINUXDO_COOKIE。")
                return False
                
            csrf_data = resp_csrf.json()
            csrf_token = csrf_data.get("csrf")
            
        except Exception as e:
            logger.error(f"解析 CSRF 响应失败: {e}")
            return False

        headers.update({
            "X-CSRF-Token": csrf_token,
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Origin": "https://linux.do",
        })

        data = {
            "login": USERNAME,
            "password": PASSWORD,
            "second_factor_method": "1",
            "timezone": "Asia/Shanghai",
        }

        try:
            resp_login = self.session.post(
                SESSION_URL, data=data, impersonate="chrome136", headers=headers
            )
            if resp_login.status_code != 200:
                logger.error(f"登录失败，状态码: {resp_login.status_code}")
                return False
        except Exception as e:
            logger.error(f"登录请求异常: {e}")
            return False

        self.print_connect_info()

        logger.info("同步 Session Cookie 到 DrissionPage...")
        cookies_dict = self.session.cookies.get_dict()
        dp_cookies = []
        for name, value in cookies_dict.items():
            dp_cookies.append({"name": name, "value": value, "domain": ".linux.do", "path": "/"})
        self.page.set.cookies(dp_cookies)

        self.page.get(HOME_URL)
        time.sleep(5)
        
        return self.check_login_success()

    def click_topic(self):
        topic_list = self.page.ele("@id=list-area").eles(".:title")
        if not topic_list:
            logger.error("未找到主题帖")
            return False
        logger.info(f"发现 {len(topic_list)} 个主题帖，随机选择10个")
        for topic in random.sample(topic_list, 10):
            self.click_one_topic(topic.attr("href"))
        return True

    @retry_decorator()
    def click_one_topic(self, topic_url):
        new_page = self.browser.new_tab()
        try:
            new_page.get(topic_url)
            if random.random() < 0.3:
                self.click_like(new_page)
            self.browse_post(new_page)
        finally:
            try:
                new_page.close()
            except Exception:
                pass

    def browse_post(self, page):
        prev_url = None
        for _ in range(10):
            scroll_distance = random.randint(550, 650)
            page.run_js(f"window.scrollBy(0, {scroll_distance})")
            
            if random.random() < 0.03:
                break

            at_bottom = page.run_js("window.scrollY + window.innerHeight >= document.body.scrollHeight")
            current_url = page.url
            if current_url != prev_url:
                prev_url = current_url
            elif at_bottom and prev_url == current_url:
                break
            time.sleep(random.uniform(2, 4))

    def run(self):
        try:
            login_res = self.login()
            if not login_res:
                logger.warning("登录验证失败，终止任务")
                return

            if BROWSE_ENABLED:
                click_topic_res = self.click_topic()
                if not click_topic_res:
                    return
                logger.info("完成浏览任务")

            self.send_notifications(BROWSE_ENABLED)
        finally:
            try:
                self.page.close()
                self.browser.quit()
            except Exception:
                pass

    def click_like(self, page):
        try:
            like_button = page.ele(".discourse-reactions-reaction-button")
            if like_button:
                like_button.click()
                time.sleep(random.uniform(1, 2))
        except Exception:
            pass

    def print_connect_info(self):
        headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"}
        try:
            resp = self.session.get("https://connect.linux.do/", headers=headers, impersonate="chrome136")
            soup = BeautifulSoup(resp.text, "html.parser")
            rows = soup.select("table tr")
            info = []
            for row in rows:
                cells = row.select("td")
                if len(cells) >= 3:
                    info.append([cells[0].text.strip(), cells[1].text.strip(), cells[2].text.strip()])
            print("--------------Connect Info-----------------")
            print(tabulate(info, headers=["项目", "当前", "要求"], tablefmt="pretty"))
        except Exception as e:
            logger.error(f"获取连接信息失败: {e}")

    def send_notifications(self, browse_enabled):
        display_name = USERNAME if USERNAME else "LinuxDo User"
        status_msg = f"✅每日登录成功: {display_name}"
        if browse_enabled:
            status_msg += " + 浏览任务完成"

        # --- Gotify 推送 ---
        if GOTIFY_URL and GOTIFY_TOKEN:
            try:
                requests.post(f"{GOTIFY_URL}/message", params={"token": GOTIFY_TOKEN}, json={"title": "LINUX DO", "message": status_msg, "priority": 1}, timeout=10)
                logger.success("Gotify 推送成功")
            except Exception as e:
                logger.error(f"Gotify 推送失败: {e}")

        # --- Server酱³ 推送 ---
        if SC3_PUSH_KEY:
            try:
                match = re.match(r"sct(\d+)t", SC3_PUSH_KEY, re.I)
                if match:
                    uid = match.group(1)
                    url = f"https://{uid}.push.ft07.com/send/{SC3_PUSH_KEY}"
                    requests.get(url, params={"title": "LINUX DO", "desp": status_msg}, timeout=10)
                    logger.success("Server酱³ 推送成功")
            except Exception as e:
                logger.error(f"Server酱³ 推送失败: {e}")

        # --- WxPusher 推送 (修复版) ---
        # 只要配置了 Token 和 UID，就通过官方接口推送
        if WXPUSH_TOKEN and WXPUSH_UID:
            try:
                url = "https://wxpusher.zjiecode.com/api/send/message"
                payload = {
                    "appToken": WXPUSH_TOKEN,
                    "content": status_msg,
                    "contentType": 1,  # 1表示文本
                    "uids": [WXPUSH_UID]
                }
                resp = requests.post(url, json=payload, timeout=10).json()
                if resp.get('code') == 1000:
                    logger.success("WxPusher 推送成功")
                else:
                    logger.error(f"WxPusher 推送失败: {resp.get('msg')}")
            except Exception as e:
                logger.error(f"WxPusher 推送异常: {str(e)}")
        else:
            logger.info("未配置 WxPusher，跳过推送")


if __name__ == "__main__":
    if not COOKIE_STR and (not USERNAME or not PASSWORD):
        print("请配置 LINUXDO_COOKIE (推荐) 或 账号密码")
        exit(1)
        
    l = LinuxDoBrowser()
    l.run()
