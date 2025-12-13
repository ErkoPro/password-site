import hashlib
import math
import requests

def calculate_entropy(password):
    charset = 0
    if any(c.islower() for c in password): charset += 26
    if any(c.isupper() for c in password): charset += 26
    if any(c.isdigit() for c in password): charset += 10
    if any(c in "!@#$%^&*()-_=+[]{}|;:,.<>/?`~" for c in password): charset += 32
    if charset == 0:
        return 0
    return round(len(password) * math.log2(charset), 2)

def check_breach(password):
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        res = requests.get(url, timeout=10)
    except Exception:
        return 0
    if res.status_code != 200:
        return 0
    for line in res.text.splitlines():
        if ":" not in line:
            continue
        h, count = line.split(":", 1)
        if h == suffix:
            try:
                return int(count)
            except:
                return 0
    return 0

# Vercel serverless entrypoint expects a function named `handler`
def handler(request):
    try:
        if request.method != "POST":
            return {"statusCode": 200, "body": {"message": "Send POST request to this endpoint (JSON: {\"password\":\"...\"})"}}

        data = request.json() or {}
        password = data.get("password", "")

        entropy = calculate_entropy(password)
        breached = check_breach(password)

        if entropy < 28:
            strength = "Very Weak"
        elif entropy < 36:
            strength = "Weak"
        elif entropy < 60:
            strength = "Medium"
        elif entropy < 128:
            strength = "Strong"
        else:
            strength = "Very Strong"

        return {
            "statusCode": 200,
            "body": {
                "entropy": entropy,
                "strength": strength,
                "breached": breached
            }
        }
    except Exception as e:
        return {"statusCode": 500, "body": {"error": "internal error", "detail": str(e)}}