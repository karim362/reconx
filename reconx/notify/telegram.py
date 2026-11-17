"""Telegram notifications."""
import requests

def send(token, chat_id, message):
    if not token or not chat_id: return False
    try:
        r = requests.post(f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": message[:4000],
                  "parse_mode": "Markdown", "disable_web_page_preview": True}, timeout=10)
        return r.status_code == 200
    except Exception: return False

def format_result(domain, live, takeover, nuclei, secrets):
    msg = f"*ReconX: {domain}*\n\nLive: `{len(live)}`\n"
    if takeover: msg += f"Takeover: *{len(takeover)}*\n"
    if nuclei: msg += f"Nuclei: *{len(nuclei)}*\n"
    if secrets: msg += f"Secrets: *{len(secrets)}*\n"
    return msg
