import imaplib
import email
from email.header import decode_header
import re
import dkim
import spf
import pickle
import pandas as pd

# Конфигурация
IMAP_SERVER = "imap.mail.ru"
EMAIL_ACCOUNT = "mycompany99@mail.ru"
PASSWORD = "7m3yVilVvt8uDSHoqAyf"

phishing_keywords = [
    'подтвердите', 'срочно', 'заблокирован', 'смените пароль', 'перейдите по ссылке',
    'безопасность', 'проверка доступа', 'подтверждение учетной записи', 'корпоративный',
    'обновление', 'восстановление', 'защита', 'вход в систему', 'аудит', 'подозрительная'
]
suspicious_domains = ['bit.ly', 'tinyurl.com', 'malicious-site.ru']

def clean_text(text):
    if text is None: return ""
    if isinstance(text, bytes):
        try: return text.decode()
        except: return text.decode('latin1')
    return text

def check_phishing_keywords(subject, body):
    subject_lower = subject.lower()
    body_lower = body.lower()
    for word in phishing_keywords:
        if word in subject_lower or word in body_lower:
            return True
    urls = re.findall(r'http[s]?://[^\s]+', body_lower)
    for url in urls:
        for domain in suspicious_domains:
            if domain in url:
                return True
    return False

def check_dkim(raw_email_bytes):
    try:
        return dkim.verify(raw_email_bytes)
    except Exception:
        return False

def check_spf(ip, sender, helo_name):
    try:
        result, _, _ = spf.check2(i=ip, s=sender, h=helo_name)
        return result == 'pass'
    except Exception:
        return False

def get_sender_ip(email_message):
    received_headers = email_message.get_all('Received', [])
    for header in received_headers:
        ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', header)
        if ip_match:
            return ip_match.group(1)
    return None

def load_ml_model(model_path="model.pkl"):
    with open(model_path, "rb") as f:
        vectorizer, clf = pickle.load(f)
    return vectorizer, clf

def predict_ml(subject, body, vectorizer, clf):
    text = (subject or "") + " " + (body or "")
    X = vectorizer.transform([text])
    pred = clf.predict(X)
    return pred[0] == 1

def get_urls(text):
    return re.findall(r'http[s]?://[^\s]+', text)

def analyze_url(url):
    risk = 0
    if any(domain in url for domain in suspicious_domains):
        risk += 3
    if url.startswith('http://'):
        risk += 2
    if len(url) > 60:
        risk += 1
    # Здесь можно добавить проверку через публичные API на фишинговость (PhishTank, VirusTotal)
    return risk

def analyze_emails():
    vectorizer, clf = load_ml_model()
    mail = imaplib.IMAP4_SSL(IMAP_SERVER)
    mail.login(EMAIL_ACCOUNT, PASSWORD)
    mail.select("inbox")
    status, messages = mail.search(None, "ALL")
    email_ids = messages[0].split()
    print(f"Всего писем: {len(email_ids)}")

    results = []

    for email_id in email_ids[-50:]:
        status, msg_data = mail.fetch(email_id, "(RFC822)")
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                raw_email = response_part[1]
                msg = email.message_from_bytes(raw_email)
                subject, encoding = decode_header(msg["Subject"])[0]
                subject = clean_text(subject)
                if encoding and isinstance(subject, bytes):
                    subject = subject.decode(encoding)
                if msg.is_multipart():
                    parts = []
                    for part in msg.walk():
                        ctype = part.get_content_type()
                        cdisp = str(part.get('Content-Disposition'))
                        if ctype == 'text/plain' and 'attachment' not in cdisp:
                            parts.append(clean_text(part.get_payload(decode=True)))
                    body = "\n".join(parts)
                else:
                    body = clean_text(msg.get_payload(decode=True))

                urls = get_urls(body)
                url_risk = sum(analyze_url(url) for url in urls)
                phishing_keywords_flag = check_phishing_keywords(subject, body)
                dkim_flag = check_dkim(raw_email)
                sender_ip = get_sender_ip(msg)
                from_header = msg.get('From', '')
                sender_email_match = re.search(r'<(.+?)>', from_header)
                sender_email = sender_email_match.group(1) if sender_email_match else from_header
                helo_name = sender_email.split('@')[-1]
                spf_flag = False
                if sender_ip:
                    spf_flag = check_spf(sender_ip, sender_email, helo_name)
                ml_flag = predict_ml(subject, body, vectorizer, clf)

                # Итоговая оценка риска
                risk_score = 0
                if phishing_keywords_flag: risk_score += 2
                if not dkim_flag: risk_score += 1
                if not spf_flag: risk_score += 1
                if ml_flag: risk_score += 3
                risk_score += url_risk

                result = [
                    subject,
                    phishing_keywords_flag,
                    ml_flag,
                    dkim_flag,
                    spf_flag,
                    sender_ip or '',
                    ", ".join(urls),
                    risk_score
                ]
                results.append(result)

    mail.logout()
    df = pd.DataFrame(results)
    df.columns = [
        "Тема письма",
        "Ключевые слова (фишинг)",
        "Фишинг по ML",
        "Проверка DKIM",
        "Проверка SPF",
        "IP отправителя",
        "Ссылки",
        "Уровень риска"
    ]
    df.to_csv("analysis_report.csv", index=False, encoding="utf-8-sig")
    print("Анализ завершен, результаты сохранены в analysis_report.csv")

if __name__ == "__main__":
    analyze_emails()
