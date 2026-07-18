from telegram import (
    Update,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
)

from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
)

from config import BOT_TOKEN, ADMIN_ID

from modules.password_checker import check_password
from modules.hash_generator import generate_hashes
from modules.ip_lookup import lookup_ip
from modules.whois_lookup import get_whois
from modules.cve_search import search_cve
from modules.virustotal import scan_url
from modules.news import get_news
from modules.report import create_report
from modules.port_scanner import scan_ports
from modules.website_scanner import scan_website

from database.database import (
    create_database,
    log_command,
    total_users,
    total_commands,
    most_used_command,
)


import logging
import os

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/bot.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger("CyberBot")

# ==============================
# START
# ==============================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):

    logger.info(
    f"{update.effective_user.username} used /start"
)

    log_command(
        update.effective_user.id,
        update.effective_user.username or "Unknown",
        "/start"
    )

    keyboard = [

        [
            InlineKeyboardButton("🔐 Password", callback_data="password"),
            InlineKeyboardButton("🔒 Hash", callback_data="hash"),
        ],

        [
            InlineKeyboardButton("🌍 IP Lookup", callback_data="ip"),
            InlineKeyboardButton("🌐 WHOIS", callback_data="whois"),
        ],

        [
            InlineKeyboardButton("🛡 CVE", callback_data="cve"),
            InlineKeyboardButton("🔍 URL Scan", callback_data="scan"),
        ],

        [
            InlineKeyboardButton("📰 News", callback_data="news"),
        ],

    ]

    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        "🛡 Welcome to Cyber Security Assistant Bot\n\n"
        "Select a tool below:",
        reply_markup=reply_markup
    )


# ==============================
# HELP
# ==============================
async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):

    log_command(
        update.effective_user.id,
        update.effective_user.username or "Unknown",
        "/help"
    )

    message = (
        "📚 Cyber Security Bot Commands\n\n"
        "/start - Start Bot\n"
        "/help - Help Menu\n"
        "/password <password>\n"
        "/hash <text>\n"
        "/ip <ip>\n"
        "/whois <domain>\n"
        "/cve <CVE-ID>\n"
        "/scan <url>\n"
        "/news\n"
        "/stats (Admin Only)"
        "/report - Generate PDF report"
        "/website - Website Security Scanner"
    )

    await update.message.reply_text(message)


# ==============================
# PASSWORD CHECKER
# ==============================
async def password(update: Update, context: ContextTypes.DEFAULT_TYPE):

    log_command(
        update.effective_user.id,
        update.effective_user.username or "Unknown",
        "/password"
    )

    if not context.args:
        await update.message.reply_text(
            "Usage:\n"
            "/password <your_password>\n\n"
            "Example:\n"
            "/password MyPassword123!"
        )
        return

    user_password = " ".join(context.args)

    strength, feedback = check_password(user_password)

    response = f"🔐 Password Strength: {strength}\n\n"

    if feedback:
        response += "\n".join(feedback)
    else:
        response += "✅ Excellent password!"

    await update.message.reply_text(response)


# ==============================
# HASH GENERATOR
# ==============================
async def hash_command(update: Update, context: ContextTypes.DEFAULT_TYPE):

    logger.info(
    f"{update.effective_user.username} used /hash"
)

    log_command(
        update.effective_user.id,
        update.effective_user.username or "Unknown",
        "/hash"
    )

    if not context.args:
        await update.message.reply_text(
            "Usage:\n"
            "/hash <text>\n\n"
            "Example:\n"
            "/hash hello"
        )
        return

    text = " ".join(context.args)

    hashes = generate_hashes(text)

    response = (
        "🔒 Hash Generator\n\n"
        f"Input: {text}\n\n"
        f"MD5:\n{hashes['MD5']}\n\n"
        f"SHA1:\n{hashes['SHA1']}\n\n"
        f"SHA256:\n{hashes['SHA256']}"
    )

    await update.message.reply_text(response)


# ==============================
# IP LOOKUP
# ==============================
async def ip_command(update: Update, context: ContextTypes.DEFAULT_TYPE):

    logger.info(
    f"{update.effective_user.username} used /ip"
)

    log_command(
        update.effective_user.id,
        update.effective_user.username or "Unknown",
        "/ip"
    )

    if not context.args:
        await update.message.reply_text(
            "Usage:\n"
            "/ip <IP Address>\n\n"
            "Example:\n"
            "/ip 8.8.8.8"
        )
        return

    ip = context.args[0]

    result = lookup_ip(ip)

    if result is None:
        await update.message.reply_text(
            "❌ Invalid IP address or lookup failed."
        )
        return

    response = (
        "🌐 IP Lookup Result\n\n"
        f"IP Address: {result['ip']}\n"
        f"Country: {result['country']}\n"
        f"Region: {result['region']}\n"
        f"City: {result['city']}\n"
        f"ISP: {result['isp']}\n"
        f"Organization: {result['org']}\n"
        f"Timezone: {result['timezone']}\n"
        f"Latitude: {result['lat']}\n"
        f"Longitude: {result['lon']}"
    )

    await update.message.reply_text(response)


# ==============================
# WHOIS LOOKUP
# ==============================
async def whois_command(update: Update, context: ContextTypes.DEFAULT_TYPE):

    log_command(
        update.effective_user.id,
        update.effective_user.username or "Unknown",
        "/whois"
    )

    if not context.args:
        await update.message.reply_text(
            "Usage:\n"
            "/whois <domain>\n\n"
            "Example:\n"
            "/whois google.com"
        )
        return

    domain = context.args[0]

    result = get_whois(domain)

    if result is None:
        await update.message.reply_text(
            "❌ Unable to retrieve WHOIS information."
        )
        return

    creation = result["creation_date"]
    if isinstance(creation, list):
        creation = creation[0]

    expiration = result["expiration_date"]
    if isinstance(expiration, list):
        expiration = expiration[0]

    nameservers = result["name_servers"]

    if isinstance(nameservers, (list, set)):
        nameservers = "\n".join(sorted(str(ns) for ns in nameservers))
    else:
        nameservers = str(nameservers)

    response = (
        "🌍 WHOIS Information\n\n"
        f"Domain: {result['domain']}\n"
        f"Registrar: {result['registrar']}\n"
        f"Creation Date: {creation}\n"
        f"Expiration Date: {expiration}\n\n"
        f"Name Servers:\n{nameservers}"
    )

    await update.message.reply_text(response)


# ==============================
# CVE SEARCH
# ==============================
async def cve_command(update: Update, context: ContextTypes.DEFAULT_TYPE):

    log_command(
        update.effective_user.id,
        update.effective_user.username or "Unknown",
        "/cve"
    )

    if not context.args:
        await update.message.reply_text(
            "Usage:\n"
            "/cve <CVE-ID>\n\n"
            "Example:\n"
            "/cve CVE-2024-4577"
        )
        return

    cve_id = context.args[0].upper()

    result = search_cve(cve_id)

    if result is None:
        await update.message.reply_text("❌ CVE not found.")
        return

    response = (
        "🛡️ CVE Information\n\n"
        f"CVE ID: {result['id']}\n\n"
        f"Severity: {result['severity']}\n"
        f"CVSS Score: {result['score']}\n\n"
        f"Published: {result['published'][:10]}\n"
        f"Last Modified: {result['modified'][:10]}\n\n"
        f"Description:\n{result['description']}"
    )

    await update.message.reply_text(response)

 # ==============================
# VIRUSTOTAL URL SCAN
# ==============================
async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):

    log_command(
        update.effective_user.id,
        update.effective_user.username or "Unknown",
        "/scan"
    )

    if not context.args:
        await update.message.reply_text(
            "Usage:\n"
            "/scan https://example.com"
        )
        return

    url = context.args[0]

    await update.message.reply_text("🔍 Scanning URL... Please wait.")

    result = scan_url(url)

    if result is None:
        await update.message.reply_text("❌ Scan failed.")
        return

    if result["malicious"] > 0:
        status = "🚨 Malicious"
    elif result["suspicious"] > 0:
        status = "⚠️ Suspicious"
    else:
        status = "✅ Safe"

    response = (
        "🔍 VirusTotal Scan\n\n"
        f"URL: {url}\n\n"
        f"Malicious: {result['malicious']}\n"
        f"Suspicious: {result['suspicious']}\n"
        f"Harmless: {result['harmless']}\n\n"
        f"Status: {status}"
    )

    await update.message.reply_text(response)


# ==============================
# CYBERSECURITY NEWS
# ==============================
async def news_command(update: Update, context: ContextTypes.DEFAULT_TYPE):

    log_command(
        update.effective_user.id,
        update.effective_user.username or "Unknown",
        "/news"
    )

    await update.message.reply_text(
        "📰 Fetching latest cybersecurity news..."
    )

    articles = get_news()

    if not articles:
        await update.message.reply_text(
            "❌ Unable to fetch news."
        )
        return

    message = "📰 Latest Cybersecurity News\n\n"

    for index, article in enumerate(articles, start=1):
        message += (
            f"{index}. {article['title']}\n"
            f"{article['url']}\n\n"
        )

    await update.message.reply_text(message)


# ==============================
# ADMIN STATS
# ==============================
async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):

    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text(
            "❌ You are not authorized."
        )
        return

    users = total_users()
    commands = total_commands()
    popular = most_used_command()

    if popular:
        command_name = popular[0]
        count = popular[1]
    else:
        command_name = "None"
        count = 0

    message = (
        "📊 Cyber Bot Statistics\n\n"
        f"👥 Total Users: {users}\n"
        f"📌 Total Commands: {commands}\n"
        f"🔥 Most Used Command: {command_name} ({count})"
    )

    await update.message.reply_text(message)


# ==============================
# PDF REPORT
# ==============================
async def report_command(update: Update, context: ContextTypes.DEFAULT_TYPE):

    log_command(
        update.effective_user.id,
        update.effective_user.username or "Unknown",
        "/report"
    )

    username = update.effective_user.username or "Unknown"

    content = (
        "Cyber Security Telegram Bot\n\n"
        "This report was generated using the Telegram Bot.\n\n"
        "Available Features:\n"
        "- Password Checker\n"
        "- Hash Generator\n"
        "- IP Lookup\n"
        "- WHOIS Lookup\n"
        "- CVE Search\n"
        "- VirusTotal Scan\n"
        "- Cybersecurity News\n"
    )

    filename = create_report(
        username,
        "Cyber Security Report",
        content
    )

    with open(filename, "rb") as pdf:
        await update.message.reply_document(
            document=pdf,
            filename=filename,
            caption="📄 Your report is ready!"
        )

# ==============================
# Button Handler
# ==============================
async def button(update: Update, context: ContextTypes.DEFAULT_TYPE):

    query = update.callback_query

    await query.answer()

    if query.data == "password":
        await query.edit_message_text(
            "🔐 Password Checker\n\n"
            "Usage:\n"
            "/password MyPassword123!"
        )

    elif query.data == "hash":
        await query.edit_message_text(
            "🔒 Hash Generator\n\n"
            "Usage:\n"
            "/hash hello"
        )

    elif query.data == "ip":
        await query.edit_message_text(
            "🌍 IP Lookup\n\n"
            "Usage:\n"
            "/ip 8.8.8.8"
        )

    elif query.data == "whois":
        await query.edit_message_text(
            "🌐 WHOIS Lookup\n\n"
            "Usage:\n"
            "/whois google.com"
        )

    elif query.data == "cve":
        await query.edit_message_text(
            "🛡 CVE Search\n\n"
            "Usage:\n"
            "/cve CVE-2024-4577"
        )

    elif query.data == "scan":
        await query.edit_message_text(
            "🔍 VirusTotal Scan\n\n"
            "Usage:\n"
            "/scan https://example.com"
        )

    elif query.data == "news":
        await query.edit_message_text(
            "📰 Latest Cybersecurity News\n\n"
            "Type:\n"
            "/news"
        )

# ==============================
# Button Handler
# ==============================

async def website_command(update: Update, context: ContextTypes.DEFAULT_TYPE):

    logger.info(
        f"{update.effective_user.username} used /website"
    )

    log_command(
        update.effective_user.id,
        update.effective_user.username or "Unknown",
        "/website"
    )

    if not context.args:

        await update.message.reply_text(
            "Usage:\n\n"
            "/website google.com"
        )
        return

    url = context.args[0]

    try:

        data = scan_website(url)

        msg = (
            "🌐 Website Security Scan\n\n"
            f"🔗 URL: {data['url']}\n"
            f"📡 Status: {data['status']}\n"
            f"🖥 Server: {data['server']}\n"
            f"🔒 HTTPS: {'✅ Yes' if data['https'] else '❌ No'}\n"
            f"⚡ Response Time: {data['response_time']} sec\n\n"
            "🛡 Security Headers\n\n"
        )

        for k, v in data["security_headers"].items():
            msg += f"• {k}\n   {v}\n\n"

        await update.message.reply_text(msg)

    except Exception as e:

        logger.error(str(e))

        await update.message.reply_text(
            f"❌ Error:\n{e}"
        )

# ==============================
# MAIN FUNCTION
# ==============================
def main():

    # Create database if it doesn't exist
    create_database()

    # Create Telegram Application
    app = Application.builder().token(BOT_TOKEN).build()

    # Register Commands
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("password", password))
    app.add_handler(CommandHandler("hash", hash_command))
    app.add_handler(CommandHandler("ip", ip_command))
    app.add_handler(CommandHandler("whois", whois_command))
    app.add_handler(CommandHandler("cve", cve_command))
    app.add_handler(CommandHandler("scan", scan_command))
    app.add_handler(CommandHandler("news", news_command))
    app.add_handler(CommandHandler("stats", stats_command))
    app.add_handler(CommandHandler("report", report_command))
    app.add_handler(CommandHandler("website", website_command))

    app.add_handler(CallbackQueryHandler(button))

    print("=" * 60)
    print("🛡️ Cyber Security Telegram Bot Started Successfully")
    print("=" * 60)
    print("Available Commands:")
    print("/start")
    print("/help")
    print("/password")
    print("/hash")
    print("/ip")
    print("/whois")
    print("/cve")
    print("/scan")
    print("/news")
    print("/stats")
    print("=" * 60)

    logger.info("Cyber Security Bot Started")

    # Start the bot
    app.run_polling(allowed_updates=Update.ALL_TYPES)
    
    app.add_handler(
    CommandHandler(
        "website",
        website_command
    )
)


# ==============================
# RUN BOT
# ==============================
if __name__ == "__main__":
    main()