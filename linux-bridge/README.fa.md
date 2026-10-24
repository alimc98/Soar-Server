# پل لینوکسی WhiteDNS

این بسته یک کلاینت headless برای تونل Soar است. روی سرور ایران (Ubuntu/Debian)
اجرا می‌شود، از طریق DNS به سرور WhiteDNS خارج وصل می‌شود و یک خروجی SOCKS5
فقط روی loopback برای 3x-ui/Xray می‌سازد.

```
کاربران VLESS
      |
      v
3x-ui / Xray روی سرور ایران
      |  outbound: socks 127.0.0.1:10886
      v
whitedns-bridge  (کلاینت Soar)
      |  تونل DNS احراز‌هویت‌شده
      v
سرور WhiteDNS در خارج
      |
      v
اینترنت
```

این با صفحهٔ «خروجی SOCKS5» خود پنل فرق دارد. آن شنونده روی سرور خارج است و
3x-ui باید مستقیماً به آن دسترسی داشته باشد؛ در قطع سراسری، سرور ایران چنین
دسترسی‌ای ندارد. پل، تونل Soar را روی سرور ایران terminate می‌کند و به 3x-ui
یک outbound محلی می‌دهد.

## پیش‌نیازها

- Ubuntu 22.04/24.04/26.04 یا Debian 12/13، معماری amd64 یا arm64، systemd.
- حساب WhiteDNS با موتور Soar.
- لینک مستقیم `soar://` یا آدرس ساب HTTPS که **در زمان نصب** در دسترس باشد.
  برای قطع سراسری، لینک مستقیم را از قبل ذخیره کنید.
- سهمیه، سرعت، سقف جریان و پورت‌های مجاز همان حساب (پیش‌فرض 80/443) اعمال می‌شوند.

## نصب

فایل release را باز کنید و لینک مستقیم را بدهید:

```bash
tar -xzf whitedns-bridge-0.1.0-linux-amd64.tar.gz
cd whitedns-bridge-0.1.0-linux-amd64
sudo bash install.sh 'soar://...'
```

نصب‌کننده پروفایل را اعتبارسنجی می‌کند، کاربر سیستمی و سرویس systemd می‌سازد،
در صورت تأیید یک رمز تصادفی برای SOCKS محلی می‌سازد، سرویس را روی
`127.0.0.1:10886` بالا می‌آورد و JSON آمادهٔ outbound را در
`/etc/whitedns-bridge/3x-ui-outbound.json` می‌نویسد.

دستورهای کاربردی:

```bash
systemctl status whitedns-bridge --no-pager
journalctl -u whitedns-bridge -f
systemctl restart whitedns-bridge
sudo bash install.sh --uninstall
```

پروفایل در `/etc/whitedns-bridge/profile` و رمز SOCKS محلی در
`/etc/whitedns-bridge/bridge.env` نگه‌داری می‌شوند و فقط برای root و گروه
`whitedns` قابل خواندن هستند.

## تنظیم 3x-ui

در 3x-ui مسیر **Xray Configs → Outbounds → Add Outbound → socks** را باز کنید و
این outbound را اضافه کنید:

```json
{
  "tag": "whitedns-bridge",
  "protocol": "socks",
  "settings": {
    "servers": [
      {
        "address": "127.0.0.1",
        "port": 10886,
        "users": [{ "user": "whitedns", "pass": "GENERATED_PASSWORD" }]
      }
    ]
  }
}
```

سپس ترافیکی را که باید از تونل برود به tag `whitedns-bridge` مسیر دهید. ساختار
معمول:

- یک inbound از نوع VLESS روی سرور ایران برای کاربران (فقط TCP؛ UDP را فعال نکنید)؛
- قاعدهٔ routing از tag آن inbound به `whitedns-bridge`؛
- یک outbound مستقیم/freedom برای مقاصد ایرانی باقی بماند؛
- DNS خود Xray روی مسیر مستقیم/داخلی بماند. کوئری UDP DNS را از پل رد نکنید؛
  پل فقط TCP را حمل می‌کند.

پل فقط SOCKS5 **CONNECT/TCP** را پشتیبانی می‌کند. UDP، QUIC و UDP ASSOCIATE
کار نمی‌کنند. VLESS روی TCP قابل استفاده است؛ فقط TCP را از پل رد کنید.

## چرا پورت SOCKS را عمومی نکنیم؟

پل عمداً آدرس غیر-loopback را قبول نمی‌کند. SOCKS5 رمز را رمزنگاری نمی‌کند و
این شنونده برای 3x-ui محلی است. اگر 3x-ui روی ماشین دیگری است، پورت را با
WireGuard یا SSH forward کنید، نه با بازکردن عمومی.

## آماده‌سازی پیش از قطع سراسری

پل فقط به هویت تونل (دامنه و کلید عمومی) و resolverهای اولیه نیاز دارد و بعد از
نصب به دسترسی به پنل نیاز ندارد. لینک مستقیم `soar://` را قبل از قطعی در پنل
بردارید، پل را نصب و تست کنید و سرویس را فعال نگه دارید. لینک ساب ممکن است
هنگام نصب کار کند ولی در قطعی به‌روزرسانی نمی‌شود؛ هویت تونل با ویرایش حساب
تغییر نمی‌کند. اگر کلید تونل را در پنل عوض کردید، پروفایل جدید را دوباره نصب
کنید.

اگر تونل آماده نمی‌شود، ممکن است resolverهای تنظیم‌شده از شبکهٔ ایران در دسترس
نباشند. آن‌ها را با resolverهایی که از همان سرور پاسخ می‌دهند جایگزین کنید و
discovery را روشن نگه دارید:

```bash
sudo systemctl edit whitedns-bridge
# [Service]
# Environment=WHITEDNS_RESOLVERS=10.202.10.202,10.202.10.102
sudo systemctl restart whitedns-bridge
```

resolver باید واقعاً تونل را حمل کند؛ resolverی که DNS عادی را جواب می‌دهد ولی
کوئری‌های تونل‌مانند را drop می‌کند به کار نمی‌آید. اگر `discovery` در پروفایل
روشن باشد، گزینه‌های داخلی `ir.txt` و `global.txt` هم امتحان می‌شوند.

## ساخت از سورس

Go 1.25 یا جدیدتر:

```bash
make test
make package
```

`make package` بسته‌های Linux amd64 و arm64 را در `dist/` می‌سازد. هر بسته شامل
فایل اجرایی، نصب‌کننده، unit سیستم‌د، مستندات، مجوز/NOTICE پروژه و پوشهٔ
`licenses/` با مجوز Soar، توضیح تغییرات و مجوز داده‌های resolver است. پوشهٔ
`third_party/soar` همان کلاینت Soar v0.2.3 با تغییرات WhiteDNS است که در
WhiteDNS Desktop استفاده می‌شود.

## گزینه‌ها

| گزینه | پیش‌فرض | کاربرد |
| --- | --- | --- |
| `-profile` | `$WHITEDNS_PROFILE` | لینک مستقیم، ساب HTTPS یا فایل |
| `-profile-file` | `/etc/whitedns-bridge/profile` | فایل حاوی لینک |
| `-listen` | `127.0.0.1:10886` | آدرس SOCKS (فقط loopback) |
| `-username`، `-password` | خالی | احراز هویت محلی اختیاری |
| `-resolvers` | لیست پروفایل | تغییر resolverهای اولیه |
| `-max-conns` | `maxStreams` پروفایل | سقف اتصال محلی |
| `-dial-timeout` | مقدار پروفایل | مهلت dial مقصد |
| `-check` | `true` | تست HTTPS احراز‌هویت‌شده در پس‌زمینه |
| `-validate` | `false` | فقط اعتبارسنجی پروفایل |

متغیرهای `WHITEDNS_PROFILE`، `WHITEDNS_PROFILE_FILE`، `WHITEDNS_SOCKS_LISTEN`،
`WHITEDNS_SOCKS_USER`، `WHITEDNS_SOCKS_PASS`، `WHITEDNS_RESOLVERS` و
`WHITEDNS_LOG_LEVEL` را می‌توان در `/etc/whitedns-bridge/bridge.env` گذاشت.

## محدودیت‌ها

- همهٔ کاربران 3x-ui از سهمیه، سرعت و سقف جریان یک حساب استفاده می‌کنند.
- فهرست پورت مجاز پنل روی سرور خارج اعمال می‌شود.
- تونل DNS با کلید عمومی سرور احراز و رمزنگاری می‌شود؛ رمز SOCKS فقط hop محلی
  را محافظت می‌کند.
- handshake حداکثر ۱۰ ثانیه و dial مطابق پروفایل محدود است.
- هر سرویس یک پروفایل را اجرا می‌کند؛ برای چند حساب، چند سرویس جدا اجرا کنید.
