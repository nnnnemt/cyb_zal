
import json
import re
import hashlib
import smtplib
import requests
import pandas as pd
import matplotlib.pyplot as plt

from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from pathlib import Path
from collections import Counter
from urllib.parse import urlparse, parse_qs
from fpdf import FPDF
from fpdf.enums import XPos, YPos

BASE = Path(__file__).parent.resolve()
USERS_FILE = BASE / "users.json"
TWEETS_FILE = BASE / "tweets.json"
HISTORY_FILE = BASE / "history.json"
ALERTS_FILE = BASE / "alerts.json"
IOCS_FILE = BASE / "iocs.json"
LOG_FILE = BASE / "alerts.log"
PDF_REPORT = BASE / "report.pdf"
HTML_REPORT = BASE / "report.html"

URL_RE = re.compile(r"https?://\S+")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

EMOT_WORDS = {
    "szok", "pilne", "skandal", "sensacja", "alarm", "natychmiast",
    "katastrofa", "kryzys", "tragedia", "dramat", "panika", "chaos",
    "eksplozja", "terror", "atak", "niebezpieczeństwo", "zagrożenie",
    "uwaga", "ostrzeżenie", "breaking", "flash", "emergency", "urgent",
    "zdrada", "spisek", "manipulacja", "propaganda", "fake", "kłamstwo"
}

BANNED = {"t.me", "bit.ly", "bad.link", "phish.example", "tinyurl.com", "short.ly"}
SUSP_THRESH = 3


class Tweet:
    def __init__(self, user, text):
        self.user = user
        self.text = text
        self.timestamp = datetime.now().isoformat()

    def to_dict(self):
        return {
            "user": self.user,
            "text": self.text,
            "timestamp": self.timestamp
        }

    @classmethod
    def from_dict(cls, data):
        tweet = cls(data["user"], data["text"])
        tweet.timestamp = data.get("timestamp", datetime.now().isoformat())
        return tweet


class User:
    def __init__(self, username, password_hash):
        self.username = username
        self.password_hash = password_hash
        self.watchlist = []
        self.keywords = ["wojna", "Putin", "Ukraina"]
        self.x_api = ""
        self.telegram_token = ""
        self.chat_id = ""

    def to_dict(self):
        return {
            "password": self.password_hash,
            "watchlist": self.watchlist,
            "keywords": self.keywords,
            "x_api": self.x_api,
            "telegram_token": self.telegram_token,
            "chat_id": self.chat_id
        }

    @classmethod
    def from_dict(cls, username, data):
        user = cls(username, data["password"])
        user.watchlist = data.get("watchlist", [])
        user.keywords = data.get("keywords", ["wojna", "Putin", "Ukraina"])
        user.x_api = data.get("x_api", "")
        user.telegram_token = data.get("telegram_token", "")
        user.chat_id = data.get("chat_id", "")
        return user


class AnalysisResult:
    def __init__(self, tweet, score, sentiment, links, cities, iocs, owner=None):
        self.user = tweet.user
        self.text = tweet.text
        self.score = score
        self.sentiment = sentiment
        self.links = links
        self.cities = cities
        self.iocs = iocs
        self.timestamp = datetime.now().isoformat()
        self.owner = owner
        self.suspicious = score >= SUSP_THRESH

    def to_dict(self):
        result = {
            "user": self.user,
            "text": self.text,
            "score": self.score,
            "sentiment": self.sentiment,
            "links": self.links,
            "cities": self.cities,
            "iocs": self.iocs,
            "timestamp": self.timestamp,
            "suspicious": self.suspicious
        }
        if self.owner:
            result["owner"] = self.owner
        return result


def load_json(path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except:
        return default


def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def init_files():
    if not USERS_FILE.exists():
        demo_user = User("demo", hashlib.sha256("demo".encode()).hexdigest())
        save_json(USERS_FILE, {"demo": demo_user.to_dict()})
    if not TWEETS_FILE.exists():
        save_json(TWEETS_FILE, [])
    for f in (HISTORY_FILE, ALERTS_FILE, IOCS_FILE):
        if not f.exists():
            save_json(f, {})


def reset_data():
    save_json(TWEETS_FILE, [])
    save_json(HISTORY_FILE, {})
    save_json(ALERTS_FILE, [])
    save_json(IOCS_FILE, {})
    print("[INFO] Dane zresetowane.")


def extract_coords(url):
    qs = parse_qs(urlparse(url).query)
    for k in ("q", "mlat", "lat", "ll"):
        if k in qs:
            parts = qs[k][0].split(",")
            try:
                return float(parts[0]), float(parts[1])
            except:
                pass
    return None


def reverse_geocode(lat, lng):
    try:
        addr = requests.get(
            f"https://nominatim.openstreetmap.org/reverse?format=json&lat={lat}&lon={lng}",
            timeout=5
        ).json().get("address", {})
        return addr.get("city") or addr.get("town") or addr.get("village")
    except:
        return None


def score_tweet(text, keywords, emotional, banned):
    score = 0
    low = text.lower()

    if any(k.lower() in low for k in keywords):
        score += 2

    if any(e in low for e in emotional):
        score += 2

    letters = [c for c in text if c.isalpha()]
    if letters and sum(1 for c in letters if c.isupper()) / len(letters) > 0.4:
        score += 1

    if any(d in url for url in URL_RE.findall(text) for d in banned):
        score += 3

    return score


def sentiment(text):
    NEG = {
        "nienawiść", "zło", "oszustwo", "atak", "zdrajca", "terror", "zabić",
        "zniszczyć", "katastrofa", "tragedia", "kłamstwo", "fake", "manipulacja",
        "propaganda", "spisek", "zagrożenie", "niebezpieczeństwo", "panika",
        "chaos", "kryzys", "dramat", "wściekłość", "gniew", "frustracja"
    }
    POS = {
        "pokój", "miłość", "dobro", "pomoc", "nadzieja", "radość", "szczęście",
        "wsparcie", "współpraca", "jedność", "solidarność", "wolność",
        "bezpieczeństwo", "stabilność", "rozwój", "postęp", "sukces",
        "zwycięstwo", "osiągnięcie", "pozytywne", "dobre", "wspaniałe"
    }

    low = text.lower()
    neg_count = sum(1 for w in NEG if w in low)
    pos_count = sum(1 for w in POS if w in low)

    if neg_count > pos_count:
        return "Negatywne"
    elif pos_count > neg_count:
        return "Pozytywne"
    else:
        return "Neutralne"


def save_history(user, results):
    h = load_json(HISTORY_FILE, {})
    h.setdefault(user, []).extend([r.to_dict() for r in results])
    save_json(HISTORY_FILE, h)


def save_alerts(alerts):
    alert_dicts = [a.to_dict() for a in alerts]
    save_json(ALERTS_FILE, alert_dicts)
    with LOG_FILE.open("a", encoding="utf-8") as f:
        for a in alerts:
            f.write(f"{datetime.now().isoformat()} | ALERT for {a.owner} | @{a.user} | score={a.score}\n")


def analyze_for_user(username, users_dict):
    user = User.from_dict(username, users_dict[username])
    tweets_data = load_json(TWEETS_FILE, [])
    tweets = [Tweet.from_dict(t) for t in tweets_data]

    to_check = [t for t in tweets if not user.watchlist or t.user in user.watchlist]
    if not to_check:
        print("[INFO] Brak tweetów do analizy.")
        input("\nEnter...")
        return

    results = []
    alerts = []

    for tweet in to_check:
        text = tweet.text
        sc = score_tweet(text, user.keywords, EMOT_WORDS, BANNED)
        sent = sentiment(text)

        links = URL_RE.findall(text)
        cities = []
        for link in links:
            coords = extract_coords(link)
            if coords:
                city = reverse_geocode(*coords)
                if city:
                    cities.append(city)

        iocs = (
                IP_RE.findall(text) +
                MD5_RE.findall(text) +
                SHA1_RE.findall(text) +
                EMAIL_RE.findall(text) +
                [urlparse(u).netloc for u in links]
        )

        result = AnalysisResult(
            tweet=tweet,
            score=sc,
            sentiment=sent,
            links=links,
            cities=cities,
            iocs=list(set(iocs)),
            owner=username
        )

        results.append(result)

        if result.suspicious:
            alerts.append(result)

    save_history(username, results)
    if alerts:
        all_alerts_data = load_json(ALERTS_FILE, [])
        existing_alerts = [analysis_result_from_dict(a) for a in all_alerts_data] if all_alerts_data else []
        all_alerts = existing_alerts + alerts
        save_alerts(all_alerts)

    print(f"[RESULT] Analiza zakończona: {len(results)} wpisów, {len(alerts)} alertów")
    input("\nEnter...")


def analysis_result_from_dict(data):
    temp_tweet = Tweet(data["user"], data["text"])
    return AnalysisResult(
        tweet=temp_tweet,
        score=data["score"],
        sentiment=data["sentiment"],
        links=data["links"],
        cities=data["cities"],
        iocs=data["iocs"],
        owner=data.get("owner")
    )


AnalysisResult.from_dict = staticmethod(analysis_result_from_dict)


def manage_watchlist(user_obj, users_dict):
    while True:
        print("\n--- WATCHLIST ---")
        for i, wd in enumerate(user_obj.watchlist, 1):
            print(f"{i}. {wd}")
        print("a) Dodaj  d) Usuń  q) Wyjście")
        ch = input("> ").strip().lower()
        if ch == "a":
            v = input("Konto: ").strip()
            if v:
                user_obj.watchlist.append(v)
                users_dict[user_obj.username] = user_obj.to_dict()
                save_json(USERS_FILE, users_dict)
        elif ch == "d":
            n = input("Numer: ").strip()
            if n.isdigit() and 1 <= int(n) <= len(user_obj.watchlist):
                user_obj.watchlist.pop(int(n) - 1)
                users_dict[user_obj.username] = user_obj.to_dict()
                save_json(USERS_FILE, users_dict)
        else:
            break


def manage_keywords(user_obj, users_dict):
    while True:
        print("\n--- KEYWORDS ---")
        for i, kw in enumerate(user_obj.keywords, 1):
            print(f"{i}. {kw}")
        print("a) Dodaj  d) Usuń  q) Wyjście")
        ch = input("> ").strip().lower()
        if ch == "a":
            v = input("Słowo: ").strip()
            if v:
                user_obj.keywords.append(v)
                users_dict[user_obj.username] = user_obj.to_dict()
                save_json(USERS_FILE, users_dict)
        elif ch == "d":
            n = input("Numer: ").strip()
            if n.isdigit() and 1 <= int(n) <= len(user_obj.keywords):
                user_obj.keywords.pop(int(n) - 1)
                users_dict[user_obj.username] = user_obj.to_dict()
                save_json(USERS_FILE, users_dict)
        else:
            break


def show_history(username):
    h = load_json(HISTORY_FILE, {}).get(username, [])
    print(f"\n--- HISTORIA ({username}) ---")
    if not h:
        print("[pusta]")
    else:
        for e in h[-20:]:
            flag = "⚠️" if e["score"] >= SUSP_THRESH else "OK"
            ts = e["timestamp"][:19]
            print(f"{flag} {ts} | @{e['user']} | score={e['score']} | {e['sentiment']}")
    input("\nEnter...")


def show_alerts():
    al = load_json(ALERTS_FILE, [])
    print(f"\n--- ALERTY ({len(al)}) ---")
    for a in al[-20:]:
        ts = a["timestamp"][:19]
        print(f"{ts} | owner={a['owner']} | @{a['user']} | score={a['score']}")
    input("\nEnter...")


def report_stats():
    tweets_data = load_json(TWEETS_FILE, [])
    words = []
    for t in tweets_data:
        words += re.findall(r'\b[a-ząćęłńóśźż]+\b', t["text"].lower())
    print("\n--- NAJCZĘSTSZE SŁOWA ---")
    for w, c in Counter(words).most_common(15):
        print(f"{w}: {c}")
    input("\nEnter...")


def top_accounts():
    tweets_data = load_json(TWEETS_FILE, [])
    scores = {}
    for t in tweets_data:
        sc = score_tweet(t["text"], [], EMOT_WORDS, BANNED)
        st = scores.setdefault(t["user"], {"sum": 0, "cnt": 0})
        st["sum"] += sc
        st["cnt"] += 1
    ranked = sorted(scores.items(), key=lambda x: x[1]["sum"] / x[1]["cnt"], reverse=True)
    print("\n--- TOP KONTA ---")
    for i, (u, st) in enumerate(ranked[:10], 1):
        avg = st["sum"] / st["cnt"]
        print(f"{i}. @{u} | avg={avg:.1f}")
    input("\nEnter...")


def filter_history(username, start, end):
    h = load_json(HISTORY_FILE, {}).get(username, [])
    if not h:
        print("Brak historii")
        input("\nEnter...")
        return

    df = pd.DataFrame(h)
    df["ts"] = pd.to_datetime(df["timestamp"].str.replace(r"\+00:00$", "", regex=True), utc=True)
    try:
        lo = pd.to_datetime(start, utc=True)
        hi = pd.to_datetime(end, utc=True)
    except:
        print("❌ Błędny format")
        input("\nEnter...")
        return

    sel = df[(df.ts >= lo) & (df.ts <= hi)]
    if sel.empty:
        print("Brak wpisów")
    else:
        for _, r in sel.iterrows():
            print(f"{r.timestamp[:19]} | @{r.user} | score={r.score}")
    input("\nEnter...")


def login_prompt(users_dict):
    u = input("Login: ").strip()
    p = input("Hasło: ").strip()
    if u in users_dict and users_dict[u]["password"] == hashlib.sha256(p.encode()).hexdigest():
        print(f"✅ Zalogowano jako {u}")
        return u
    print("❌ Nieprawidłowe dane")
    return None


def register_prompt(users_dict):
    u = input("Nowy login: ").strip()
    if not u or u in users_dict:
        print("❌ Nieprawidłowy login")
        return None
    p = input("Hasło: ").strip()

    new_user = User(u, hashlib.sha256(p.encode()).hexdigest())
    users_dict[u] = new_user.to_dict()
    save_json(USERS_FILE, users_dict)
    print("✅ Zarejestrowano")
    return u


def user_menu(username, users_dict):
    user_obj = User.from_dict(username, users_dict[username])

    while True:
        print(f"\n--- MENU ({username}) ---")
        print("1) Watchlista")
        print("2) Dodaj tweet")
        print("3) Keywords")
        print("4) X API")
        print("5) Telegram API")
        print("6) Analiza")
        print("7) Historia")
        print("8) Alerty")
        print("9) Słowa")
        print("10) Top konta")
        print("11) Filtruj")
        print("12) Reset danych")
        print("0) Wyloguj")
        ch = input("> ").strip()

        if ch == "1":
            manage_watchlist(user_obj, users_dict)
        elif ch == "2":
            a = input("Autor: ").strip()
            t = input("Tekst: ").strip()
            if a and t:
                new_tweet = Tweet(a, t)
                tweets_data = load_json(TWEETS_FILE, [])
                tweets_data.append(new_tweet.to_dict())
                save_json(TWEETS_FILE, tweets_data)
                print("✅ Tweet dodany")
        elif ch == "3":
            manage_keywords(user_obj, users_dict)
        elif ch == "4":
            x = input("X API Key: ").strip()
            if x and not re.match(r"^[A-Za-z0-9]{20,}$", x):
                print("❌ Format")
            else:
                user_obj.x_api = x
                users_dict[username] = user_obj.to_dict()
                save_json(USERS_FILE, users_dict)
                print("✅ Zapisano")
        elif ch == "5":
            tok = input("Telegram token: ").strip()
            chat = input("CHAT_ID: ").strip()
            if tok and not re.match(r"^\d+:[A-Za-z0-9_-]+$", tok):
                print("❌ Format")
            elif chat and not chat.isdigit():
                print("❌ CHAT_ID musi być liczbą")
            else:
                user_obj.telegram_token = tok
                user_obj.chat_id = chat
                users_dict[username] = user_obj.to_dict()
                save_json(USERS_FILE, users_dict)
                print("✅ Zapisano")
        elif ch == "6":
            analyze_for_user(username, users_dict)
        elif ch == "7":
            show_history(username)
        elif ch == "8":
            show_alerts()
        elif ch == "9":
            report_stats()
        elif ch == "10":
            top_accounts()
        elif ch == "11":
            s = input("Start YYYY-MM-DD: ")
            e = input("Koniec: ")
            filter_history(username, s, e)
        elif ch == "12":
            reset_data()
        elif ch == "0":
            break
        else:
            print("❌ Opcja nieznana")


def main():
    init_files()
    users_dict = load_json(USERS_FILE, {})

    while True:
        print("\n=== OSINT APP ===")
        print("1) Logowanie")
        print("2) Rejestracja")
        print("3) Reset danych i wyjście")
        print("0) Wyjście")
        c = input("> ").strip()

        if c == "1":
            u = login_prompt(users_dict)
            if u:
                user_menu(u, users_dict)
        elif c == "2":
            r = register_prompt(users_dict)
            if r:
                users_dict = load_json(USERS_FILE, {})
        elif c == "3":
            reset_data()
            break
        elif c == "0":
            break
        else:
            print("❌ Nieznana opcja")


if __name__ == "__main__":
    main()
