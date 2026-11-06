# بررسی ابزار JS Extractor Pro (v2.0.0)

> تاریخ بررسی: 2026-11-04 — کد بررسی‌شده: commit `1967db6` (کل منطق در `js_extractor/cli.py`، حدود ۱۸۱۰ خط)
>
> موارد علامت‌خورده با ✅ با تست عملی تأیید شده‌اند؛ بقیه از روی خواندن کد هستند.

---

## ۱. خلاصه

ابزار یک CLI پایتونی برای recon جاوااسکریپت است: JS های صفحه را جمع می‌کند، beautify می‌کند و روی آن‌ها تحلیل استاتیک (endpoint، پارامتر، secret، نسخه کتابخانه + CVE) اجرا می‌کند و به ابزارهای بیرونی (katana، gau، httpx، retire، semgrep، LinkFinder، wappalyzer) وصل می‌شود.

ایده و پوشش قابلیت‌ها خوب است، اما چند مشکل جدی دارد:

- **دو آسیب‌پذیری امنیتی** که هدفِ مخرب می‌تواند علیه خودِ پنتستر استفاده کند (Path Traversal در source map و XSS در گزارش HTML).
- **نشت کوکی و توکن احراز هویت** به همه‌ی دامنه‌های third-party.
- **قابلیت بازیابی source map اصلاً کار نمی‌کند** (کتابخانه‌ی اشتباه + API اشتباه).
- چند باگ منطقی و نبود قابلیت‌های پایه‌ای مثل `--proxy` و خروجی JSON.

> **وضعیت کلی (2026-11-06):** دور دوم رفع‌ها انجام شد — تحلیل‌گر CVE (querybatch + امتیاز عددی CVSS + تشخیص از نام فایل)، سقف اندازه‌ی beautify، ورودی چند-هدفه (`-l/--list`)، تحلیل محلی بدون شبکه (`--input-dir`)، مدیریت `Ctrl+C`، محافظت `os.isatty`/`NO_COLOR`، و تک‌منبعه‌کردن نسخه (حذف `setup.py`). فاز تحلیل به تابع مشترک `_analyze_and_report` جدا شد. هر ۱۰ تست‌سوئیت سبز است. موارد باقی‌مانده: الگوهای بیشتر secret + entropy، بهبود دقت regex پارامتر/endpoint، و تحلیل روی متن خام به‌جای beautify‌شده.

---

## ۲. قابلیت‌ها

### جمع‌آوری JS
| قابلیت | فلگ | توضیح |
|---|---|---|
| استخراج استاتیک | (پیش‌فرض) | `requests` + BeautifulSoup؛ تگ‌های `<script src>` و inline |
| استخراج داینامیک | `--dynamic` | Playwright/Chromium؛ همه‌ی requestهای نوع `script` و inline های DOM زنده |
| دنبال‌کردن import ها | (پیش‌فرض، `--no-imports`) | `import ... from`، `require()`، `import()` — فقط مسیرهای نسبی `./` و `../` با پسوند `.js` |
| Web/Service Worker | (پیش‌فرض، `--no-workers`) | `new Worker(...)` و `navigator.serviceWorker.register(...)` |
| Source map | (پیش‌فرض، `--no-sourcemaps`) | خواندن `sourceMappingURL` (فایل یا base64 inline) — **فعلاً خراب، بخش ۳ را ببینید** |
| Crawl عمیق | `--katana`, `--katana-depth` | فقط URL های `.js` از خروجی katana |
| URL های تاریخی | `--gau`, `--gau-providers` | Wayback/OTX/CommonCrawl/URLScan، با `--subs` |
| بررسی زنده بودن | `--httpx-probe` | فیلتر خروجی gau با httpx |
| احراز هویت | `--cookie`, `--jwt`, `--header` | به requests، Playwright، katana و httpx پاس داده می‌شود |

### تحلیل
| قابلیت | فلگ | روش |
|---|---|---|
| تشخیص فریم‌ورک | همیشه | امضای regex برای React، Next، Vue، Nuxt، Angular، Svelte، Webpack، Vite، GraphQL و... |
| Endpoint ها | `--endpoints` | ۴ الگوی regex + علامت‌گذاری «hidden» (admin، internal، debug، ...) |
| پارامترها | `--params` | query string، کلید آبجکت‌ها، `.append/.set/.get`، `:param` مسیرها، `name=` |
| Secret ها | `--secrets` | ۱۴ الگو: AWS، Google، GitHub، GitLab، Slack، OpenAI، Facebook، JWT، Private Key، ... |
| نسخه کتابخانه + CVE | `--cve` | ۲۷ الگوی banner و پرس‌وجو از OSV.dev (اکوسیستم npm) |
| ابزارهای بیرونی | `--wappalyzer`, `--retire`, `--semgrep`, `--linkfinder` | فقط اگر روی PATH باشند؛ در غیر این صورت با warning رد می‌شوند |
| همه با هم | `--all-analysis` | |

### خروجی
- فایل‌های beautify‌شده در `external/` و `inline/`، `sourcemap_recovered/`
- `--merge` ← `ALL_SCRIPTS_MERGED.js`
- `--report` ← `report.html`
- فایل‌های متنی: `endpoints.txt`، `endpoints_hidden.txt`، `params_wordlist.txt`، `cve_report.txt`، `retire_report.txt`، `semgrep_report.txt`، `linkfinder_endpoints.txt`، `gau_all.txt`/`gau_alive.txt`

### نقاط قوت
- اجرای subprocess ها همه به‌صورت لیست (بدون `shell=True`) ← Command Injection ندارد.
- ابزارهای اختیاری با `shutil.which` چک می‌شوند و نبودشان کل اجرا را خراب نمی‌کند.
- `install.sh` قبل از نصب هر ابزار سؤال می‌پرسد.
- secret ها در ترمینال و گزارش mask می‌شوند.
- README کامل و مرتب.

---

## ۳. مشکلات

### 🔴 بحرانی (امنیتی)

> **وضعیت (2026-11-04):** هر سه مورد 3.1 تا 3.3 رفع و با تست رگرسیون تأیید شدند.

#### 3.1 ✅ Path Traversal / نوشتن فایل دلخواه از طریق Source Map
`cli.py:412`
```python
safe_path = re.sub(r"[^\w/.\-]", "_", src_file).lstrip("/")
dest = sm_dir / safe_path
```
کاراکترهای `.` و `/` مجاز هستند، پس `../` باقی می‌ماند. یک سایت مخرب (یا هر هدفی که source map آن قابل کنترل است) می‌تواند در فیلد `sources` مقداری مثل
`webpack:///../../../../../../../home/user/.bashrc` بگذارد و ابزار محتوای `sourcesContent` را **روی ماشین پنتستر** هر جایی بنویسد.

تست: ورودی `webpack:///../../../../../../../tmp/pwned.sh` به `/tmp/pwned.sh` resolve شد.

**رفع:** بعد از ساخت مسیر، `dest.resolve()` را با `sm_dir.resolve()` مقایسه کنید (`is_relative_to`) یا اجزای `..` را حذف کنید.

> نکته: این باگ الان به‌خاطر باگ 3.4 عملاً اجرا نمی‌شود، ولی به‌محض درست‌کردن source map فعال می‌شود.

#### 3.2 ✅ Stored XSS در `report.html`

> **وضعیت (2026-11-06): رفع شد.** کل تولید گزارش به `js_extractor/report.py` منتقل شد و هر مقدار مشتق‌شده از هدف با `html.escape(quote=True)` و `href` ها با یک تابع `safe_href` (فقط `http(s)`) پاکسازی می‌شوند.
`generate_report()` (خطوط 1126–1376) هیچ داده‌ای را escape نمی‌کند. endpoint ها، پارامترها، پیام‌های semgrep، نتایج LinkFinder، URL ها و حتی `target_url` (داخل `<title>` و `href`) مستقیم وارد HTML می‌شوند. هدف کافی است در JS خود رشته‌ای مثل `"/api/<img src=x onerror=...>"` بگذارد تا موقع باز کردن گزارش، کد در مرورگر پنتستر اجرا شود (در `file://` که دسترسی به فایل‌های محلی هم می‌تواند داشته باشد).

**رفع:** همه‌ی مقادیر با `html.escape(..., quote=True)` escape شوند و برای `href` فقط `http(s)` مجاز باشد.

#### 3.3 ✅ نشت کوکی و Authorization به دامنه‌های third-party
`cli.py:1471-1473`
```python
session.headers.update(build_headers(args))   # Authorization
session.cookies.update(build_cookies(args))   # بدون domain
```
کوکی‌ها بدون domain در jar قرار می‌گیرند و هدر `Authorization` روی session است؛ پس به **همه** درخواست‌ها فرستاده می‌شوند: CDN ها، Google Analytics، import های cross-origin، source map های خارجی، URL های gau و ... . تست: کوکی `session=abc` برای `https://evil-cdn.example/x.js` ارسال شد.

همین مشکل در حالت `--dynamic` هم هست (`extra_http_headers` روی کل context) و در `httpx` برای همه‌ی ساب‌دامین‌های gau.

**رفع:** هدرهای auth را فقط برای hostname هدف (یا یک allowlist) اضافه کنید؛ کوکی را با `domain=` ست کنید.

---

### 🟠 مهم (باگ‌هایی که قابلیت را از کار می‌اندازند)

#### 3.4 ✅ بازیابی Source Map هرگز کار نمی‌کند

> **وضعیت (2026-11-04): رفع شد.** پارسر با `json` بازنویسی شد و وابستگی `python-sourcemap` حذف شد. پیدا کردن map از طریق هدر `SourceMap`/`X-SourceMap` و حدس `<url>.map` هم اضافه شد. هر bundle حالا پوشه‌ی جداگانه دارد.
- در `setup.py`/`pyproject.toml` وابستگی `python-sourcemap>=0.5` آمده، ولی **چنین پکیجی در PyPI وجود ندارد**. پس `pip install ".[sourcemaps]"` و `".[full]"` شکست می‌خورند.
- پکیج واقعی `sourcemap` (نسخه 0.2.1) هم شیء `SourceMapIndex` برمی‌گرداند که فیلد `sources_content` **ندارد** (تست شد: فقط `index, line_index, lookup, raw, sources, tokens`). خط `sm.sources_content.get(...)` در `cli.py:408` خطای `AttributeError` می‌دهد که توسط `except Exception: continue` بی‌صدا بلعیده می‌شود ← همیشه ۰ فایل بازیابی می‌شود.

**رفع:** اصلاً کتابخانه لازم نیست؛ JSON را با `json.loads` بخوانید و `sources` و `sourcesContent` را zip کنید. همچنین هدر HTTP `SourceMap`/`X-SourceMap` و حدس `<url>.map` هم اضافه شود.

#### 3.5 تایم‌اوت = از دست رفتن کل نتایج

> **وضعیت (2026-11-04): رفع شد.** خروجی جزئی katana/gau/httpx حفظ می‌شود و فلگ `--tool-timeout` اضافه شد.
در `run_katana`، `run_gau` و `run_httpx_probe` پیام «using partial results» چاپ می‌شود ولی `return []` برمی‌گردد. خروجی جزئی (`e.stdout`) دور ریخته می‌شود. تایم‌اوت‌ها (180/300 ثانیه) هم قابل تنظیم نیستند و gau با `--subs` روی دامنه‌های بزرگ تقریباً همیشه تایم‌اوت می‌شود.

#### 3.6 کرش `--wappalyzer` وقتی خروجی لیست باشد

> **وضعیت (2026-11-04): رفع شد.** هر دو شکل خروجی (لیست و دیکشنری) و categories رشته‌ای پشتیبانی می‌شوند.
`cli.py:922`
```python
techs = data.get("technologies", data if isinstance(data, list) else [])
```
اگر `data` لیست باشد، `.get` روی لیست صدا زده می‌شود ← `AttributeError` و کل برنامه کرش می‌کند. ضمناً پکیج npm `wappalyzer` از ۲۰۲۳ deprecated/بسته شده و احتمالاً نصبش کار نمی‌کند.

#### 3.7 `--dynamic` بدون مدیریت خطا

> **وضعیت (2026-11-04): رفع شد.** به‌جای `networkidle` اجباری، اول `load` و بعد `networkidle` با سقف ۱۰ ثانیه؛ هر خطا (نبود Chromium، خطای ناوبری) دیگر برنامه را کرش نمی‌کند. inline ها strip می‌شوند و تکرار ندارند.
`page.goto(..., wait_until="networkidle", timeout=30000)` روی سایت‌هایی که polling/websocket دارند معمولاً تایم‌اوت می‌شود و استثنا گرفته نمی‌شود ← کل اجرا کرش می‌کند. `time.sleep(2)` هم بعد از جمع‌آوری inline ها است و بی‌اثر است.

#### 3.8 ✅ فیلتر کلمات نویز در پارامترها نصفه کار می‌کند

> **وضعیت (2026-11-04): رفع شد.** مجموعه‌ی نویز lowercase شد.
`cli.py:707` مقدار `p.lower()` را با `_PARAM_NOISE` مقایسه می‌کند، ولی آن مجموعه شامل `toString`، `forEach` و ... با حروف بزرگ است ← هرگز match نمی‌شوند.

#### 3.9 تحلیل‌ها فقط روی `external/` اجرا می‌شوند

> **وضعیت (2026-11-04): رفع شد.** retire، semgrep و LinkFinder حالا `external/`، `inline/` و `sourcemap_recovered/` را اسکن می‌کنند. کد first-party بازیابی‌شده وارد تحلیل endpoint/param/secret می‌شود. کد `node_modules` فقط برای retire و تشخیص نسخه‌ی کتابخانه استفاده می‌شود و از بقیه‌ی تحلیل‌ها حذف می‌شود.
retire، semgrep و LinkFinder فقط پوشه‌ی `external/` را اسکن می‌کنند؛ `inline/` و مهم‌تر از همه `sourcemap_recovered/` (کد اصلی و unminified) اسکن نمی‌شوند. secret/endpoint/param هم کد بازیابی‌شده از source map را شامل نمی‌شوند.

#### 3.10 Worker و import فقط در فایل‌های external جستجو می‌شوند

> **وضعیت (2026-11-04): رفع شد.** inline ها هم برای Worker/Service Worker و import جستجو می‌شوند.
`find_workers` و `find_js_imports` روی inline ها و HTML اجرا نمی‌شوند؛ در حالی که ثبت Service Worker معمولاً در inline script است.

---

### 🟡 متوسط (دقت، Scope، کارایی)

#### Scope و رفتار شبکه
- **خروج از Scope:** *(رفع شد: `--scope any|domain|host`، `--include-host`، `--exclude-host`)* gau با `--subs` هاردکد شده و همه‌ی JS های ساب‌دامین‌ها دانلود می‌شوند؛ import/worker/source map هم به هر دامنه‌ای دنبال می‌شوند. برای پنتست مجاز این خطرناک است. فلگ `--scope`/`--no-subs` لازم است.
- **بدون محدودیت و همزمانی:** *(رفع شد: `--threads`، `--rate-limit`، `--max-files`)* دانلود کاملاً ترتیبی با تایم‌اوت ۲۰ ثانیه و sleep ثابت. چند هزار URL از gau یعنی چند ساعت. `--threads`، `--rate-limit` و `--max-files` نیست.
- **JS های مرده از gau:** *(رفع شد: `--wayback`)* URL های تاریخیِ مرده دانلود نمی‌شوند، در حالی که اصل ارزش gau همین است. می‌توان نسخه‌ی آرشیو را از `web.archive.org/web/<ts>id_/<url>` گرفت.
- **ناسازگاری TLS:** *(رفع شد: `--insecure`/`--ca-cert`؛ Playwright هم حالا فقط با `--insecure` خطای TLS را نادیده می‌گیرد)* Playwright با `ignore_https_errors=True` اجرا می‌شود ولی requests با `verify=True`؛ روی هدف‌های self-signed (محیط‌های داخلی) حالت استاتیک شکست می‌خورد. فلگ `--insecure` نیست.
- **محدودیت حجم و نوع محتوا نیست:** *(رفع شد: `--max-size` و رد کردن صفحه‌های HTML)* صفحه‌ی soft-404 (HTML با کد 200) به‌عنوان `.js` ذخیره و تحلیل می‌شود؛ فایل‌های چند صدمگابایتی کل حافظه را می‌گیرند.

#### کشف JS
- *(رفع شد: runtime و chunk map وبپک، `.e()`، مسیرهای مطلق و `.mjs`)* regex import فقط مسیرهای نسبی `./`/`../` با `.js` را می‌گیرد؛ chunk های webpack/Vite (مسیر مطلق، بدون پسوند، `__webpack_require__.u`، chunk map) گرفته نمی‌شوند.
- *(رفع شد)* `<link rel="modulepreload">` و `<link rel="preload" as="script">` (رایج در Vite/Next) در حالت استاتیک نادیده گرفته می‌شوند.
- فیلتر katana/gau فقط `.js` است؛ `.mjs`، `.jsx` و `.cjs` حذف می‌شوند.
- `<script type="application/json">` و `application/ld+json` و template ها هم به‌عنوان JS beautify می‌شوند (البته `__NEXT_DATA__` مفید است، ولی بهتر است جدا ذخیره شوند).
- **inline تکراری در `--dynamic`:** نسخه‌ی استاتیک `.strip()` می‌شود ولی نسخه‌ی DOM نه ← مقایسه‌ی `b not in static_inline` شکست می‌خورد و بلاک‌ها دوبار ذخیره می‌شوند.

#### دقت تحلیل‌ها
- **Secret:** *(رفع شد: ~۳۵ الگو، severity، entropy و فیلتر placeholder، decode کردن JWT؛ حالا هر یافته نام فایل و خط واقعی دارد، در `secrets.json` ذخیره می‌شود و ماسک برای مقادیر کوتاه درست شد. الگوهای بیشتر و entropy هنوز مانده.)* شماره‌ی خط نسبت به رشته‌ی الحاق‌شده‌ی همه فایل‌هاست، نه فایل واقعی ← تقریباً بی‌فایده. نام فایل در نتیجه نیست. **هیچ فایلی برای secret ها ذخیره نمی‌شود** (برخلاف بقیه‌ی تحلیل‌ها). الگوهای مهمی مثل Stripe (`sk_live_`)، Twilio، SendGrid، Mailgun، Firebase config، Sentry DSN، Mapbox، Azure و URL های حاوی credential نیستند. entropy check و حذف placeholder ها (`password: "password"`) هم نیست. ماسک ترمینال برای مقادیر ۶ تا ۱۰ کاراکتری کل مقدار را نشان می‌دهد.
- **Endpoint:** *(رفع شد: تطبیق کلمه‌ی کامل، HTTP method و file:line)* کلمات «hidden» مثل `test` و `dev` روی `latest`، `device`، `developer` هم match می‌شوند (FP زیاد). endpoint ها به URL مطلق resolve نمی‌شوند و منبع (کدام فایل) ثبت نمی‌شود.
- **Params:** *(رفع شد: فقط کلیدهایی که به درخواست می‌رسند)* الگوی `[{,]\s*key\s*:` تمام کلیدهای آبجکت‌ها در bundle را برمی‌دارد ← wordlist پر از نویز (هزاران کلید داخلی React/webpack).
- **CVE:** *(رفع شد 2026-11-06: اسکن نام فایل روی URL ها (`jquery-3.5.1.min.js`)، یک درخواست `querybatch` برای همه‌ی کتابخانه‌ها + واکشی جزئیات فقط برای vuln های یافت‌شده (با cache)، و تبدیل vector به امتیاز عددی CVSS v3.x و باند NONE/LOW/MEDIUM/HIGH/CRITICAL در `cvss_score`.)* الگوهایی مثل `React\s+v?(\d+\.\d+\.\d+)` با `IGNORECASE` روی هر رشته‌ی «react 1.2.3» match می‌شوند؛ الگوهای مبتنی بر نام فایل (`jquery-3.5.1.min.js`) روی URL ها اجرا نمی‌شوند، فقط روی محتوا. فیلد «severity» در عمل vector رشته‌ای CVSS است نه عدد. از `querybatch` در OSV استفاده نمی‌شود.
- *(رفع شد 2026-11-06: فلگ `--max-beautify-size` (پیش‌فرض ۲MB)؛ فایل‌های بزرگ‌تر به‌جای reformat کامل، یک line-split سریع می‌گیرند تا یک bundle غول‌پیکر کل اجرا را هنگ نکند.)* beautify با `unescape_strings=True` و تحلیل روی متن beautify‌شده: jsbeautifier پایتونی روی bundle های چند مگابایتی بسیار کند است، و تحلیل regex روی متن خام سریع‌تر و دقیق‌تر است.

---

### 🔵 جزئی / کیفیت کد و مستندات

- *(رفع شد: کد به ماژول‌های `net`، `discovery/`، `analyzers/`، `integrations/` و `report` تقسیم شد)* - کل کد در یک فایل ۱۸۱۰ خطی؛ **هیچ تستی** وجود ندارد. *(بخش تست رفع شد: `tests/` با ۷ suite و CI روی GitHub Actions)*
- `if all_contents_merge is not None` همیشه true است؛ `all_contents_merge` حتی بدون `--merge` در حافظه ساخته می‌شود.
- *(رفع شد 2026-11-06: در `try/except` پیچیده شد، به `sys.stdout.isatty` fallback می‌کند و `NO_COLOR` را احترام می‌گذارد.)* `os.isatty(sys.stdout.fileno())` در سطح ماژول؛ در محیط‌هایی که stdout فایل‌دیسکریپتور ندارد موقع import کرش می‌کند. رنگ روی Windows Terminal مدرن هم کلاً غیرفعال است.
- منطق ساخت هدر/کوکی سه بار تکرار شده (`build_headers`، `extract_dynamic`، ...).
- *(رفع شد 2026-11-06: `setup.py` حذف شد و نسخه تک‌منبعه شد — `pyproject.toml` آن را به‌صورت پویا از `js_extractor.__version__` می‌خواند؛ با یک build تأیید شد.)*
- docstring می‌گوید `python3 js_extractor.py` ولی فایل `js_extractor/cli.py` است؛ help فلگ `--params` می‌گوید `params.txt` ولی فایل `params_wordlist.txt` است؛ README پوشه‌ی `sourcemap_recovered/` را در ساختار خروجی ذکر نکرده.
- `--jwt` و `--cookie` روی خط فرمان در `ps` و history دیده می‌شوند؛ امکان خواندن از متغیر محیطی یا فایل بهتر است.
- *(رفع شد 2026-11-06: `KeyboardInterrupt` در `main()` گرفته می‌شود، پیام تمیز `[Aborted]` و خروج با کد ۱۳۰ به‌جای traceback.)*
- *(رفع شد: `--fail-on` با exit code 3)* exit code همیشه 0 است (حتی اگر secret/CVE پیدا شود) ← در pipeline قابل استفاده نیست.

---

## ۴. قابلیت‌های مهمی که ندارد

| قابلیت | چرا مهم است |
|---|---|
| ✅ `--proxy` (مثلاً `http://127.0.0.1:8080`) — *رفع شد* | برای پنتستر ضروری است که ترافیک در Burp دیده شود |
| ✅ ورودی چند هدف (`-l targets.txt` / stdin) — *رفع شد* | هر هدف در زیرپوشه‌ی خود؛ خطوط نامعتبر رد می‌شوند؛ بدترین exit code برگردانده می‌شود |
| ✅ خروجی JSON (`results.json`، `--json`، `--fail-on`) — *رفع شد* | برای ادغام با ابزارهای دیگر و nuclei/ffuf |
| ✅ `--threads` / `--rate-limit` / `--max-files` / `--max-size` / `--tool-timeout` — *رفع شد* | سرعت و رعایت محدودیت هدف |
| ✅ `--insecure` و `--ca-cert` — *رفع شد* | هدف‌های self-signed |
| ✅ `--scope` / `--include-host` / `--exclude-host` / `--auth-scope` — *رفع شد* | جلوگیری از اسکن خارج از محدوده |
| ✅ تحلیل دایرکتوری/فایل محلی (`--input-dir`) — *رفع شد* | بدون شبکه؛ فایل‌های محلی را beautify و با همان آنالایزرها تحلیل می‌کند |
| ✅ دانلود نسخه‌ی آرشیوی Wayback (`--wayback`) — *رفع شد* | JS های حذف‌شده |
| ✅ بازیابی chunk های webpack/Next.js/Vite — *رفع شد* | پوشش SPA های مدرن |
| ✅ *(رفع شد: `--dom`)* تشخیص DOM sink/source ساده (`innerHTML`، `eval`، `postMessage`، `location.hash`) | الان کاملاً به semgrep وابسته است |

---

## ۵. اولویت پیشنهادی رفع

1. **3.1** Path Traversal در source map
2. **3.2** Escape در گزارش HTML
3. **3.3** محدود کردن کوکی/هدر auth به دامنه‌ی هدف
4. **3.4** بازنویسی source map با `json` و حذف وابستگی ناموجود `python-sourcemap`
5. **3.5 تا 3.7** مدیریت تایم‌اوت و خطاهای کرش‌کننده
6. افزودن `--proxy`، `--insecure`، scope و خروجی JSON
7. ذخیره‌ی secret ها با نام فایل و خط درست، و اجرای تحلیل‌ها روی `inline/` و `sourcemap_recovered/`
8. شکستن `cli.py` به ماژول‌ها و نوشتن تست برای regex ها
