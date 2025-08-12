import os, sys, shlex
from crontab import CronTab

def schedule_scan(time_str, scan_path):
    hour, minute = map(int, time_str.split(":"))
    cron = CronTab(user=True)
    project_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'run_maldefender.py'))
    py = shlex.quote(sys.executable)
    cmd = f'{py} {shlex.quote(project_path)} --scan {shlex.quote(scan_path)}'
    cron.remove_all(comment='maldefender-scan')
    job = cron.new(command=cmd, comment='maldefender-scan')
    job.minute.on(minute); job.hour.on(hour)
    cron.write()
    print(f"[+] Scheduled daily {time_str} for: {scan_path}")
