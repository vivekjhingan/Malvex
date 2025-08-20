import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from email.utils import formataddr
from pathlib import Path
import json
from datetime import datetime, timedelta

def send_weekly_report(sender_email, password, recipient_email):
    report_path = Path("maldefender/logs/weekly_report.json")
    if not report_path.exists():
        print("Weekly report log not found.")
        return

    with report_path.open("r") as f:
        data = json.load(f)

    cutoff = datetime.now().date() - timedelta(days=7)
    recent = [d for d in data if datetime.fromisoformat(d["date"]).date() >= cutoff]

    total_scans = sum(d["scans"] for d in recent)
    total_threats = sum(d["threats"] for d in recent)

    logo_path = "/home/kali/maldefender/Antivirus-Software/maldefender/malvex.png"

    # Professional-looking HTML
    html = f"""
    <html>
    <body style="font-family: 'Segoe UI', Tahoma, sans-serif; background-color: #f9f9f9; padding: 30px;">
        <div style="max-width: 600px; margin: auto; background-color: #ffffff; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.05); padding: 30px;">
            <div style="text-align:center; margin-bottom: 20px;">
                <img src="cid:malvexlogo" style="width: 120px;">
                <h2 style="color: #003366; margin-top: 15px;">MalDefender Weekly Security Report</h2>
            </div>
            <div style="font-size: 16px; color: #333;">
                <p><strong>Scans Run:</strong> {total_scans}</p>
                <p><strong>Threats Detected:</strong> {total_threats}</p>
                <p><strong>Reporting Period:</strong> Last 7 Days</p>
                <hr style="border: none; border-top: 1px solid #ccc; margin: 20px 0;">
                <p style="font-style: italic; color: #555;">
                    Stay secure,<br>
                    <strong style="color: #003366;">The Malvex Security Team</strong> 
                </p>
            </div>
        </div>
        <p style="text-align: center; font-size: 12px; color: #999; margin-top: 20px;">
            © {datetime.now().year} Malvex Cybersecurity Inc. All rights reserved.
        </p>
    </body>
    </html>
    """

    # Prepare email
    msg = MIMEMultipart("related")
    msg["Subject"] = "MalDefender Weekly Security Report"
    msg["From"] = formataddr(("Malvex", sender_email))
    msg["To"] = recipient_email

    alt = MIMEMultipart("alternative")
    plain_text = f"Scans Run: {total_scans}\nThreats Detected: {total_threats}\nReporting Period: Last 7 Days"
    alt.attach(MIMEText(plain_text, "plain"))
    alt.attach(MIMEText(html, "html"))
    msg.attach(alt)

    # Embed logo
    if Path(logo_path).exists():
        with open(logo_path, "rb") as img:
            logo = MIMEImage(img.read())
            logo.add_header("Content-ID", "<malvexlogo>")
            logo.add_header("Content-Disposition", "inline", filename="malvex.png")
            msg.attach(logo)
    else:
        print("Logo image not found!")

    try:
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login(sender_email, password)
        server.send_message(msg)
        server.quit()
        print("Branded weekly report email sent.")
    except Exception as e:
        print(f"Email failed: {e}")
