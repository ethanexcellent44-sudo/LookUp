# SAFEGUARD NEXUS - Face Obstruction Alert System Setup

## Overview
The system now detects when a person attempts entry with a **covered or hidden face**. When detected, it automatically sends alerts via **Telegram** and **Email** to the security team.

## How It Works

### Detection Flow
1. **Person Detection**: When a visitor checks in, the system detects if a human body is present
2. **Face Detection**: It checks if a face can be detected in the image
3. **Obstruction Detection**: If a body is present but **NO FACE is found**, an alert is triggered
4. **Alert Dispatch**: Telegram and Email notifications are sent immediately to security team

### Alert Status
When an obstruction is detected:
- **Face Status**: `OBSTRUCTION_ALERT`
- **Visitor Entry**: Still logs the person (for security records)
- **Security Team**: Receives immediate notifications

---

## Setup Instructions

### 1. Telegram Setup

#### Step 1: Create a Telegram Bot
1. Open Telegram and message **@BotFather**
2. Send command: `/newbot`
3. Follow the prompts to create your bot
4. Save the **BOT TOKEN** (looks like: `123456789:ABCDefGHijklmNoPQRstUVwxyz`)

#### Step 2: Get Your Chat ID
1. Message your newly created bot anything
2. Visit this URL in your browser (replace TOKEN):
   ```
   https://api.telegram.org/botTOKEN/getUpdates
   ```
3. Look for `"chat":{"id":123456789}` - that's your **CHAT ID**

#### Step 3: Set Environment Variables
```bash
export TELEGRAM_BOT_TOKEN="your_bot_token_here"
export TELEGRAM_CHAT_ID="your_chat_id_here"
```

**For Persistent Setup** (add to `.bashrc` for Linux):
```bash
echo 'export TELEGRAM_BOT_TOKEN="your_token"' >> ~/.bashrc
echo 'export TELEGRAM_CHAT_ID="your_id"' >> ~/.bashrc
source ~/.bashrc
```

---

### 2. Email Setup (Using Gmail)

#### Step 1: Enable 2FA on Gmail
1. Go to [Google Account Security](https://myaccount.google.com/security)
2. Enable **2-Step Verification**

#### Step 2: Create App Password
1. Go back to [Google Account Security](https://myaccount.google.com/security)
2. Find **App passwords** (under 2FA settings)
3. Select **Mail** and **Windows Computer**
4. Copy the generated **16-character password**

#### Step 3: Set Environment Variables
```bash
export SENDER_EMAIL="your_email@gmail.com"
export SENDER_PASSWORD="your_16_char_app_password"
export ALERT_EMAIL="security_team@example.com"
export SMTP_SERVER="smtp.gmail.com"
export SMTP_PORT="587"
```

**For Persistent Setup**:
```bash
echo 'export SENDER_EMAIL="your_email@gmail.com"' >> ~/.bashrc
echo 'export SENDER_PASSWORD="your_app_password"' >> ~/.bashrc
echo 'export ALERT_EMAIL="security@example.com"' >> ~/.bashrc
source ~/.bashrc
```

#### For Other Email Services
- **Outlook**: `smtp.outlook.com:587`
- **Yahoo**: `smtp.mail.yahoo.com:587`
- **Custom**: Check your email provider's SMTP settings

---

### 3. Start the App with Alerts Enabled

```bash
cd /home/pythoncoder/Desktop/FACEGUARD
source .venv/bin/activate

# Set environment variables (if not in .bashrc)
export TELEGRAM_BOT_TOKEN="your_token"
export TELEGRAM_CHAT_ID="your_id"
export SENDER_EMAIL="your_email@gmail.com"
export SENDER_PASSWORD="your_app_password"
export ALERT_EMAIL="security@example.com"

# Start the app
python3 app.py
```

---

## API Endpoints

### Get Obstruction Alerts
```
GET /api/obstruction-alerts?limit=50
Headers: Authorization required (login)
Response: List of all obstruction alerts
```

### Resolve an Alert
```
POST /api/obstruction-alerts/<alert_id>/resolve
Headers: Authorization required (login)
Response: Confirmation message
```

---

## Dashboard Features

### Security Team Dashboard
1. View all **Obstruction Alerts** in admin dashboard
2. See visitor name, timestamp, and alert type
3. Mark alerts as **Resolved**
4. Export alerts for security reports

### Alert Status Codes
- `OBSTRUCTION_ALERT`: Person detected with covered face
- `TRIGGERED`: Alert has been sent to security team
- `RESOLVED`: Security team acknowledged the alert

---

## Testing Alerts

### Test Telegram Alert
```python
from app import send_telegram_alert
send_telegram_alert("Test message: Face obstruction detected!", "TEST")
```

### Test Email Alert
```python
from app import send_email_alert
send_email_alert("Test Subject", "Test message body", "TEST")
```

---

## Troubleshooting

### Alerts not sending?
1. ✓ Check environment variables are set: `echo $TELEGRAM_BOT_TOKEN`
2. ✓ Verify internet connection
3. ✓ Check Telegram bot token is valid
4. ✓ For Gmail: Verify 2FA and App Password are correct

### Face obstruction not detecting?
1. Ensure visitor photo/video is clear
2. System detects body + no face = obstruction alert
3. Low lighting may affect detection

### Database errors?
- Obstruction alerts table is created automatically on first run
- Check file permissions for `safeguard_vault.db`

---

## Security Notes

⚠️ **DO NOT** hardcode credentials in the code!
- Always use **environment variables**
- Never commit `.env` files to version control
- Use app-specific passwords (not your main Gmail password)
- Restrict alert email recipients to authorized personnel only

---

## Sample Alert Message

**Telegram Alert:**
```
🚨 OBSTRUCTION ALERT

Person detected with obstructed/hidden face at gate entry.
Visitor: John Doe
Time: 2026-05-07 09:15:30
```

**Email Alert:**
```
Subject: [OBSTRUCTION] Face Obstruction Detected

SECURITY ALERT - OBSTRUCTION

A person attempted entry with a covered or hidden face.
Visitor Name: John Doe
Location: Main Gate
Time: 2026-05-07 09:15:30
Security action may be required.
System: SAFEGUARD NEXUS
```

---

## For More Help
Contact your system administrator or check logs for error details.
