import ssl, socket, datetime, requests, whois
from bs4 import BeautifulSoup

DOMAINS = [
    "inkythuatso.com",
    "vinadesign.vn",
    "inthenhua.com",
    "inpp.com.vn",
    "intoroi.vn",
    "inanbrochure.com",
    "inquangcao.com",
    "inantem.com",
    "indecal.com.vn",
    "inhiflex.com",
    "innamecard.net",
    "innhanh.com.vn",
    "inthucdon.com",
    "vietnamprinting.com",
    "muasamnhanh.com",
    "bannerstandstore.com",
    "canvas.com.vn",
    "catbedecal.com",
    "congtyinan.com",
    "congtyinnhanh.com",
    "congtyinnhanh.com.vn",
    "congtyinnhanh.vn",
    "digitalprinting.vn",
    "dvquangcao.com",
    "giayinanh.com",
    "in-an.com",
    "inancatalogue.com",
    "inanmoichatlieu.com",
    "inannhanh.com",
    "inanquangcao.vn",
    "inaogiare.com",
    "inbanner.com.vn",
    "inbaobi.vn",
    "incardvisit.net",
    "indanhthiep.net",
    "indanhthiep.vn",
    "indecalgiare.vn",
    "inhiflex.net",
    "inhoadon.vn",
    "inkts.com",
    "inkts.com.vn",
    "inkts.vn",
    "innhanh.net",
    "innhanhgiare.com",
    "inqualuuniem.com",
    "intembaohanh.com.vn",
    "intemdecal.vn",
    "intemnhan.com.vn",
    "intemvo.com.vn",
    "inthe.vn",
    "inthenhanvien.com",
    "inthenhua.com.vn",
    "inthenhua.net",
    "inthenhua.vn",
    "inthetu.com",
    "inthiepcuoi.com",
    "inuv.com.vn",
    "inuv.vn",
    "invipcard.com",
    "kex.vn",
    "painting.com.vn",
    "posterquangcao.com",
    "printing.com.vn",
    "standee.vn",
    "thegioiinkythuatso.com",
    "thegioithenhua.com",
    "thenhua.com.vn",
    "vieclamvui.com",
    "trungtamxe.com",
    "muabannhanh.com",
    "trungtammoigioi.com",
    "nhanhdedang.com"
]


def check_ssl(domain):
    hostname = domain.replace("https://","").replace("http://","").split("/")[0]
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
        s.settimeout(5)
        s.connect((hostname, 443))
        cert = s.getpeercert()
        exp_date = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        days_left = (exp_date - datetime.datetime.utcnow()).days
        return exp_date, days_left

def check_http(domain):
    try:
        r = requests.get(domain, timeout=10)
        return r.status_code, r.text
    except Exception as e:
        return str(e), ""

def check_assets(domain, html, tag, attr):
    errors = []
    try:
        soup = BeautifulSoup(html, "html.parser")
        links = [tag[attr] for tag in soup.find_all(tag) if tag.has_attr(attr)]
        for link in links:
            if link.startswith("//"):
                link = "https:" + link
            elif link.startswith("/"):
                link = domain.rstrip("/") + link
            try:
                r = requests.get(link, timeout=10)
                if r.status_code != 200:
                    errors.append(f"{link} → HTTP {r.status_code}")
            except Exception as e:
                errors.append(f"{link} → {e}")
    except Exception as e:
        errors.append(f"ParseError: {e}")
    return errors

def check_domain_expiration(domain):
    try:
        hostname = domain.replace("https://","").replace("http://","").split("/")[0]
        w = whois.whois(hostname)
        exp_date = w.expiration_date
        if isinstance(exp_date, list):  # sometimes returns list
            exp_date = exp_date[0]
        days_left = (exp_date - datetime.datetime.utcnow()).days
        return exp_date, days_left
    except Exception as e:
        return None, f"WHOIS Error: {e}"

if __name__ == "__main__":
    rows = []
    for d in DOMAINS:
        try:
            # SSL & HTTP
            ssl_exp, ssl_days = check_ssl(d)
            status, html = check_http(d)

            # Asset checks
            css_errors = check_assets(d, html, "link", "href") if isinstance(status, int) and status == 200 else []
            js_errors = check_assets(d, html, "script", "src") if isinstance(status, int) and status == 200 else []
            img_errors = check_assets(d, html, "img", "src") if isinstance(status, int) and status == 200 else []

            # Domain WHOIS
            domain_exp, domain_days = check_domain_expiration(d)

            # Error conditions
            errors = []
            if ssl_days <= 30: errors.append("SSL Expiring Soon")
            if status != 200: errors.append(f"HTTP {status}")
            if css_errors: errors.append(f"{len(css_errors)} CSS errors")
            if js_errors: errors.append(f"{len(js_errors)} JS errors")
            if img_errors: errors.append(f"{len(img_errors)} IMG errors")
            if isinstance(domain_days, int) and domain_days <= 30:
                errors.append("Domain Expiring Soon")

            if errors:
                ssl_html = (
                    f"<span class='badge red'>Expired</span>" if ssl_days <= 0 else
                    f"<span class='badge orange'>{ssl_days} ngày</span>" if ssl_days <= 30 else
                    f"<span class='badge green'>{ssl_days} ngày</span>"
                )
                domain_html = (
                    f"<span class='badge red'>Expired</span>" if isinstance(domain_days, int) and domain_days <= 0 else
                    f"<span class='badge orange'>{domain_days} ngày</span>" if isinstance(domain_days, int) and domain_days <= 30 else
                    f"<span class='badge green'>{domain_days} ngày</span>" if isinstance(domain_days, int) else
                    f"<span class='badge red'>{domain_days}</span>"
                )
                status_html = (
                    f"<span class='badge red'>HTTP {status}</span>" if status != 200 else
                    f"<span class='badge green'>HTTP {status}</span>"
                )

                css_html = "<br>".join(css_errors) if css_errors else "<span class='badge green'>OK</span>"
                js_html = "<br>".join(js_errors) if js_errors else "<span class='badge green'>OK</span>"
                img_html = "<br>".join(img_errors) if img_errors else "<span class='badge green'>OK</span>"

                rows.append((ssl_days, f"""
                <tr>
                    <td>{d}</td>
                    <td>{ssl_exp}</td>
                    <td>{ssl_html}</td>
                    <td>{status_html}</td>
                    <td>{domain_exp}</td>
                    <td>{domain_html}</td>
                    <td>{css_html}</td>
                    <td>{js_html}</td>
                    <td>{img_html}</td>
                </tr>
                """))
        except Exception as e:
            rows.append((-1, f"<tr><td>{d}</td><td colspan=8 style='color:red'>Error: {e}</td></tr>"))

    rows.sort(key=lambda x: x[0])
    rows_html = "".join([r[1] for r in rows])

    if not rows_html:
        rows_html = "<tr><td colspan=9 style='color:green; text-align:center;'>✅ Tất cả domain đều OK</td></tr>"

    html = f"""
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Domain Monitor Report</title>
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; margin: 20px; background: #f9fafb; color: #333; }}
            h2 {{ margin-bottom: 5px; }}
            .timestamp {{ color: #666; font-size: 0.9em; margin-bottom: 20px; }}
            table {{ border-collapse: collapse; width: 100%; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
            th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; vertical-align: top; }}
            th {{ background: #f3f4f6; }}
            tr:nth-child(even) {{ background: #fafafa; }}
            .badge {{ padding: 4px 8px; border-radius: 6px; font-size: 0.85em; font-weight: bold; }}
            .green {{ background: #d1fae5; color: #065f46; }}
            .orange {{ background: #fef3c7; color: #92400e; }}
            .red {{ background: #fee2e2; color: #991b1b; }}
        </style>
    </head>
    <body>
        <h2>🚨 Domain Monitor Report (Chỉ hiển thị domain lỗi)</h2>
        <div class="timestamp">Generated at: {datetime.datetime.utcnow()} UTC</div>
        <table>
            <tr>
                <th>Domain</th>
                <th>SSL Expiration</th>
                <th>SSL Days Left</th>
                <th>HTTP Status</th>
                <th>Domain Expiration</th>
                <th>Domain Days Left</th>
                <th>CSS Status</th>
                <th>JS Status</th>
                <th>IMG Status</th>
            </tr>
            {rows_html}
        </table>
    </body>
    </html>
    """

    with open("report.html", "w", encoding="utf-8") as f:
        f.write(html)
