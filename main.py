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
                    if attempt == retries - 1:  # 最后一次尝试
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

# 读取环境变量
USERNAME = os.environ.get("LINUXDO_USERNAME")
PASSWORD = os.environ.get("LINUXDO_PASSWORD")
COOKIE_STR = os.environ.get("LINUXDO_COOKIE") # 新增 Cookie 变量

BROWSE_ENABLED = os.environ.get("BROWSE_ENABLED", "true").strip().lower() not in [
    "false",
    "0",
    "off",
]
if not USERNAME:
    USERNAME = os.environ.get("USERNAME")
if not PASSWORD:
    PASSWORD = os.environ.get("PASSWORD")
    
GOTIFY_URL = os.environ.get("GOTIFY_URL")  # Gotify 服务器地址
GOTIFY_TOKEN = os.environ.get("GOTIFY_TOKEN")  # Gotify 应用的 API Token
SC3_PUSH_KEY = os.environ.get("SC3_PUSH_KEY")  # Server酱³ SendKey
WXPUSH_URL = os.environ.get("WXPUSH_URL")  # wxpush 服务器地址
WXPUSH_TOKEN = os.environ.get("WXPUSH_TOKEN")  # wxpush 的 token

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
            # 检查 current-user ID
            user_ele = self.page.ele("@id=current-user")
            if user_ele:
                logger.success("✅ 登录验证成功 (找到 current-user)")
                return True
            
            # 备用方案：检查是否含有头像元素
            if "avatar" in self.page.html:
                logger.success("✅ 登录验证成功 (找到 avatar)")
                return True
                
        except Exception:
            pass
        return False

    def login(self):
        logger.info("开始登录流程...")

        # ---------------------------------------------------------------------
        # 方案 A: 优先尝试 Cookie 登录 (推荐)
        # ---------------------------------------------------------------------
        if COOKIE_STR:
            logger.info("检测到 LINUXDO_COOKIE 配置，尝试通过 Cookie 免密登录...")
            try:
                # 1. 准备 Cookie 列表 (这是修复的关键点)
                dp_cookies = []
                for item in COOKIE_STR.split(';'):
                    if '=' in item:
                        # 只分割第一个等号，防止值里面也有等号
                        key, value = item.strip().split('=', 1)
                        # 构建 DrissionPage 需要的字典格式
                        dp_cookies.append({
                            "name": key, 
                            "value": value, 
                            "domain": ".linux.do", 
                            "path": "/"
                        })

                # 2. 一次性设置所有 Cookies
                # 之前报错是因为 set.cookies 不支持 name=... 这种参数，必须传列表
                self.page.set.cookies(dp_cookies)

                # 3. 设置 requests Session Headers
                headers = {
                    "Cookie": COOKIE_STR
                }
                self.session.headers.update(headers)

                logger.info("Cookie 设置完毕，正在前往主页验证...")
                self.page.get(HOME_URL)
                time.sleep(3)  # 等待页面加载

                # 验证是否登录成功
                if self.check_login_success():
                    return True
                else:
                    logger.warning("Cookie 登录失效 (可能是 Cookie 过期)，尝试回退到账号密码登录...")
            except Exception as e:
                logger.error(f"Cookie 登录过程出错: {e}")
                logger.info("尝试回退到账号密码登录...")

        # ---------------------------------------------------------------------
        # 方案 B: 原有的账号密码登录 (易被 Cloudflare 拦截)
        # ---------------------------------------------------------------------
        if not USERNAME or not PASSWORD:
            logger.error("未配置账号密码，且 Cookie 登录失败/未配置。无法继续。")
            return False

        logger.info("尝试使用账号密码登录...")
        
        # Step 1: Get CSRF Token
        logger.info("获取 CSRF token...")
        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Referer": LOGIN_URL,
        }
        
        try:
            resp_csrf = self.session.get(CSRF_URL, headers=headers, impersonate="chrome136")
            
            # 检查是否被 WAF 拦截 (返回 HTML 而不是 JSON)
            if resp_csrf.status_code == 403 or "<html" in resp_csrf.text[:100].lower():
                logger.error("❌ 获取 CSRF 失败: GitHub IP 可能被 Cloudflare 拦截 (403 Forbidden / Challenge Page)")
                logger.error("建议配置 'LINUXDO_COOKIE' 环境变量以跳过此步骤。")
                return False
                
            csrf_data = resp_csrf.json()
            csrf_token = csrf_data.get("csrf")
            logger.info(f"CSRF Token obtained: {csrf_token[:10]}...")
            
        except Exception as e:
            logger.error(f"解析 CSRF 响应失败: {e}")
            return False

        # Step 2: Login Request
        logger.info("正在发送登录请求...")
        headers.update(
            {
                "X-CSRF-Token": csrf_token,
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Origin": "https://linux.do",
            }
        )

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

            if resp_login.status_code == 200:
                response_json = resp_login.json()
                if response_json.get("error"):
                    logger.error(f"登录接口返回错误: {response_json.get('error')}")
                    return False
                logger.info("登录接口请求成功!")
            else:
                logger.error(f"登录失败，状态码: {resp_login.status_code}")
                logger.error(resp_login.text[:200]) # 只打印前200字符防止刷屏
                return False
        except Exception as e:
            logger.error(f"登录请求异常: {e}")
            return False

        self.print_connect_info()  # 打印连接信息

        # Step 3: Pass cookies to DrissionPage
        logger.info("同步 Session Cookie 到 DrissionPage...")
        cookies_dict = self.session.cookies.get_dict()
        dp_cookies = []
        for name, value in cookies_dict.items():
            dp_cookies.append(
                {
                    "name": name,
                    "value": value,
                    "domain": ".linux.do",
                    "path": "/",
                }
            )
        self.page.set.cookies(dp_cookies)

        logger.info("导航至 linux.do...")
        self.page.get(HOME_URL)
        time.sleep(5)
        
        if self.check_login_success():
            return True
        else:
            logger.error("登录后页面验证失败")
            return False

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
            if random.random() < 0.3:  # 0.3 * 30 = 9
                self.click_like(new_page)
            self.browse_post(new_page)
        finally:
            try:
                new_page.close()
            except Exception:
                pass

    def browse_post(self, page):
        prev_url = None
        # 开始自动滚动，最多滚动10次
        for _ in range(10):
            # 随机滚动一段距离
            scroll_distance = random.randint(550, 650)  # 随机滚动 550-650 像素
            logger.info(f"向下滚动 {scroll_distance} 像素...")
            page.run_js(f"window.scrollBy(0, {scroll_distance})")
            logger.info(f"已加载页面: {page.url}")

            if random.random() < 0.03:  # 33 * 4 = 132
                logger.success("随机退出浏览")
                break

            # 检查是否到达页面底部
            at_bottom = page.run_js(
                "window.scrollY + window.innerHeight >= document.body.scrollHeight"
            )
            current_url = page.url
            if current_url != prev_url:
                prev_url = current_url
            elif at_bottom and prev_url == current_url:
                logger.success("已到达页面底部，退出浏览")
                break

            # 动态随机等待
            wait_time = random.uniform(2, 4)  # 随机等待 2-4 秒
            logger.info(f"等待 {wait_time:.2f} 秒...")
            time.sleep(wait_time)

    def run(self):
        try:
            login_res = self.login()
            if not login_res:  # 登录
                logger.warning("登录验证失败，终止任务")
                return

            if BROWSE_ENABLED:
                click_topic_res = self.click_topic()  # 点击主题
                if not click_topic_res:
                    logger.error("点击主题失败，程序终止")
                    return
                logger.info("完成浏览任务")

            self.send_notifications(BROWSE_ENABLED)  # 发送通知
        finally:
            try:
                self.page.close()
            except Exception:
                pass
            try:
                self.browser.quit()
            except Exception:
                pass

    def click_like(self, page):
        try:
            # 专门查找未点赞的按钮
            like_button = page.ele(".discourse-reactions-reaction-button")
            if like_button:
                logger.info("找到未点赞的帖子，准备点赞")
                like_button.click()
                logger.info("点赞成功")
                time.sleep(random.uniform(1, 2))
            else:
                logger.info("帖子可能已经点过赞了")
        except Exception as e:
            logger.error(f"点赞失败: {str(e)}")

    def print_connect_info(self):
        logger.info("获取连接信息")
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        }
        try:
            resp = self.session.get(
                "https://connect.linux.do/", headers=headers, impersonate="chrome136"
            )
            soup = BeautifulSoup(resp.text, "html.parser")
            rows = soup.select("table tr")
            info = []

            for row in rows:
                cells = row.select("td")
                if len(cells) >= 3:
                    project = cells[0].text.strip()
                    current = cells[1].text.strip() if cells[1].text.strip() else "0"
                    requirement = cells[2].text.strip() if cells[2].text.strip() else "0"
                    info.append([project, current, requirement])

            print("--------------Connect Info-----------------")
            print(tabulate(info, headers=["项目", "当前", "要求"], tablefmt="pretty"))
        except Exception as e:
            logger.error(f"获取连接信息失败: {e}")

    def send_notifications(self, browse_enabled):
        # 优先使用 Cookie 里的名字，如果没有则用环境变量，都没有则显示 "User"
        display_name = USERNAME if USERNAME else "LinuxDo User"
        status_msg = f"✅每日登录成功: {display_name}"
        if browse_enabled:
            status_msg += " + 浏览任务完成"

        if GOTIFY_URL and GOTIFY_TOKEN:
            try:
                response = requests.post(
                    f"{GOTIFY_URL}/message",
                    params={"token": GOTIFY_TOKEN},
                    json={"title": "LINUX DO", "message": status_msg, "priority": 1},
                    timeout=10,
                )
                response.raise_for_status()
                logger.success("消息已推送至Gotify")
            except Exception as e:
                logger.error(f"Gotify推送失败: {str(e)}")
        else:
            logger.info("未配置Gotify环境变量，跳过通知发送")

        if SC3_PUSH_KEY:
            match = re.match(r"sct(\d+)t", SC3_PUSH_KEY, re.I)
            if not match:
                logger.error(
                    "❌ SC3_PUSH_KEY格式错误，未获取到UID，无法使用Server酱³推送"
                )
                return

            uid = match.group(1)
            url = f"https://{uid}.push.ft07.com/send/{SC3_PUSH_KEY}"
            params = {"title": "LINUX DO", "desp": status_msg}

            attempts = 5
            for attempt in range(attempts):
                try:
                    response = requests.get(url, params=params, timeout=10)
                    response.raise_for_status()
                    logger.success(f"Server酱³推送成功: {response.text}")
                    break
                except Exception as e:
                    logger.error(f"Server酱³推送失败: {str(e)}")
                    if attempt < attempts - 1:
                        sleep_time = random.randint(180, 360)
                        logger.info(f"将在 {sleep_time} 秒后重试...")
                        time.sleep(sleep_time)

        if WXPUSH_URL and WXPUSH_TOKEN:
            try:
                response = requests.post(
                    f"{WXPUSH_URL}/wxsend",
                    headers={
                        "Authorization": WXPUSH_TOKEN,
                        "Content-Type": "application/json",
                    },
                    json={"title": "LINUX DO", "content": status_msg},
                    timeout=10,
                )
                response.raise_for_status()
                logger.success(f"wxpush 推送成功: {response.text}")
            except Exception as e:
                logger.error(f"wxpush 推送失败: {str(e)}")
        else:
            logger.info("未配置 WXPUSH_URL 或 WXPUSH_TOKEN，跳过通知发送")


if __name__ == "__main__":
    # 放宽检查：只要有 COOKIE 或者有 账号+密码 就可以运行
    if not COOKIE_STR and (not USERNAME or not PASSWORD):
        print("Error: Missing credentials.")
        print("Please set 'LINUXDO_COOKIE' (Recommended for GitHub Actions)")
        print("OR set 'LINUXDO_USERNAME' and 'LINUXDO_PASSWORD' (May be blocked by Cloudflare)")
        exit(1)
        
    l = LinuxDoBrowser()
    l.run()
