import os
from crontab import CronTab

def schedule_scan(time_str, scan_path):
    """
    Schedule a scan at the specified time (24h format: 'HH:MM') using cron.
    """
    hour, minute = map(int, time_str.split(":"))
    cron = CronTab(user=True)

    # Absolute path to run_malvex.py
    project_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'run_malvex.py'))
    command = f'python3 {project_path} --scan {scan_path}'

    # Remove previous jobs
    cron.remove_all(comment='malvex-scan')

    job = cron.new(command=command, comment='malvex-scan')
    job.minute.on(minute)
    job.hour.on(hour)
    cron.write()

    print(f"[+] Scheduled scan daily at {time_str} for folder: {scan_path}")
