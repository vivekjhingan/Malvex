# run with: python3 send_weekly.py
from maldefender.emailer import send_weekly_report

# Provide credentials securely!
try:
    send_weekly_report("malvexsidhu@gmail.com", "eojr tske caiu myjb", "azoluqman62@gmail.com")
    print("Email sent!")
except Exception as e:
    print(f"Failed to send email: {e}")
    
