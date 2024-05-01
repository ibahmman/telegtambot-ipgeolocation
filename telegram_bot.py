import logging, requests, json
from portscan import PortScan
from telegram import Update
from telegram.ext import (Application, CommandHandler, ContextTypes, MessageHandler, filters)

# لاگ ربات در ترمینال
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__) 

# تپکن ربات تلگرام پس از ساخت در بات فادر
TELEGRAMBOT_TOKEN = "6751419487:AAET3Ejjy4IFZ55p6kijUaXPGpuq5biBs0g"

# توکن در وبسایت https://www.ip2location.io/ 
IP2LOCATION_TOKEN = "ED99B3FC98405278CF11B280703E5859"

# پارامتر های پایه هدرز و پارامس برای استفاده در کتابخونه رکوئست
HEADERS = {'content-type': 'application/json'}
PARAMS = {'key': IP2LOCATION_TOKEN, 'format': 'json'}

# آدرس ای پی آی برای دریافت لوکیشن آی پی
URL_IP2LOCATION = "https://api.ip2location.io/"

# آدرس ای پی آی برای دریافت هویز دامنه
URL_DOMAINWHOIS = "https://api.ip2whois.com/v2/"

# بررسی الگو درست دامنه.
def valid_domain(address):
    """
    الگوی درست دامنه به این گونه که رشته ی دریافت شده با کاراکتر نقطه بخش بندی شود.
    در صورتی که به دو و یا سه بخش بخش بندی شد دامنه درست وارد شده است.
    """
    try:
        address = address.split('.')
        if len(address) == 2 or len(address) == 3:
            return True
    except:
        pass
    return False

# بررسی الگو درست آی پی ورژن ۴
def valid_ip(address):
    """
    الگوی درست آی پی ورژن ۴ به اینگونه که رشته با کاراکتر نقطه بخش بندی شود.
    تایپ همه بخش ها به عدد اینتجر ویرایش شود سپس هر عدد بررسی شود که میان ۰ تا ۲۵۵ بوده باشد.
    """
    try:
        host_bytes = address.split('.')
        valid = [int(b) for b in host_bytes]
        valid = [b for b in valid if b >= 0 and b<=255]
        return len(host_bytes) == 4 and len(valid) == 4
    except:
        return False

# بررسی پورت در بازه ی مناسب
def valid_port(port):
    """
    الگوی درست یک پورت به اینگونه که عدد دریافتی میان ۰ تا ۶۵۵۳۵ بوده باشد.
    """
    try:
        if int(port) < 65535 and int(port) > 0:
            return True
    except:
        pass
    return False

def valid_portscan(address):
    """
    الگوی درست برای شروع به پورت اسکن به اینگونه که ابتدا رشته با کاراکتر : بخش بندی شود.
    اکنون میبایست دارای دو بخش بوده باشد که بخش یک آی پی ورژن چهار و بخش دو پورت مناسب بوده باشد.
    هر دو بخش با فانکشن های از پیش ساخته شده بررسی شوند در صورتی که هر دو دارای پاسخ درست بودند پورت اسکت انجام شود.
    """
    try:
        address = address.split(':')
        if valid_ip(address[0]) and valid_port(address[1]):
            return True
    except:
        pass
    return False

# کانورت کردن کد کشور به عکس پرچم
def get_country_flag(country_code: str) -> str:
    country_flags = {
        'IR': '🇮🇷',
        'FI': '🇫🇮',
        'DE': '🇩🇪',
        'US': '🇺🇲',
        'NL': '🇳🇱',
        'FR': '🇲🇫',
        'IT': '🇮🇹',
        'IL': '🇮🇱'
    }

    if country_code in country_flags:
        return country_flags[country_code]
    else :
        return '🏳'


def ip_to_message(json: json) -> str:
    """
    فانکشن یک جیسون از داده های آی پی که از وبسرویس مورد استفاده دریافت کرده است میگیرد.
    سپس پیام استاندادری درست کرده و متن پیام را باز میگرداند.
    """
    country_flag = get_country_flag(json['country_code'])
    message = f""".
    {json['ip']}
    {json['country_name']} {country_flag}
    Timezone: {json['time_zone']}
    
    """
    return message


def domain_to_message(json: json) -> json:
    """
    فانکشن یک جیسون از داده های دامنه که از وبسرویس مورد استفاده دریافت کرده است میگیرد.
    سپس پیام استاندادری درست کرده و متن پیام را باز میگرداند.
    """
    country_flag = get_country_flag(json['registrant']['country'])
    message = f""".
    {json['domain']}
    Country {country_flag}
    nameservers:
    {json['nameservers'][0]}
    {json['nameservers'][1]}

    """
    return message


def portscan_to_message(address, is_open=False):
    """
    فانکشن در دو پارامتر آدرس هدف و وضعیت باز یا بسته بودن پورت را دریافت کرده است میگیرد.
    سپس پیام استاندادری درست کرده و متن پیام را باز میگرداند.
    """
    match is_open:
        case True:
            return f'{address} 🟢'
        case False:
            return f'{address} 🔴'


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(""".
    send me a valid ipv4 or domain address.
    """)


async def echo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    if valid_ip(text):
        PARAMS['ip'] = text
        response = requests.get(url=URL_IP2LOCATION, headers=HEADERS, params=PARAMS).json()
        await update.message.reply_text(ip_to_message(response))
    
    elif valid_domain(text):
        PARAMS['domain'] = text
        response = requests.get(url=URL_DOMAINWHOIS, headers=HEADERS, params=PARAMS).json()
        await update.message.reply_text(domain_to_message(response))    
    elif valid_portscan(text):
        host, port = text.split(':')
        try:
            scanner = PortScan(host, port, thread_num=500, show_refused=False, 
                               wait_time=1, stop_after_count=True)
            open_port_discovered = scanner.run()

            assert open_port_discovered[0][1] == int(port), 'error'
            message = portscan_to_message(text, True)
        except AssertionError as e:
            message = portscan_to_message(text, False)
        except:
            message = portscan_to_message(text, False)
        await update.message.reply_text(message)

def main() -> None:
    application = Application.builder().token(TELEGRAMBOT_TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, echo))
    application.run_polling()


if __name__ == "__main__":
    main()

