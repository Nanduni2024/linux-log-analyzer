import re
from datetime import datetime
from collections import defaultdict

log_file = "/var/log/auth.log"

# Data structures
failed_logins = 0
invalid_users = []
successful_logins = []
sudo_failures = 0
attack_patterns = []
failed_by_ip = defaultdict(int)
failed_by_user = defaultdict(int)
time_patterns = []

# Regex patterns
failed_pass_pattern = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
invalid_user_pattern = re.compile(r"Invalid user (\S+) from (\S+)")
sudo_fail_pattern = re.compile(r"sudo.*authentication failure")
success_pattern = re.compile(r"Accepted password for (\S+) from (\S+)")
ssh_close_pattern = re.compile(r"Connection closed by authenticating user (\S+)")

print("[*] Analyzing auth.log...")

try:
    with open(log_file, "r") as file:
        for line in file:
            # 1. Failed password attempts (with user & IP)
            match = failed_pass_pattern.search(line)
            if match:
                failed_logins += 1
                user = match.group(1)
                ip = match.group(2)
                failed_by_user[user] += 1
                failed_by_ip[ip] += 1
                
                # Track time if available (first few chars of line)
                if len(line) > 15:
                    time_patterns.append(line[:15])
            
            # 2. Invalid user attempts (hackers trying fake users)
            match = invalid_user_pattern.search(line)
            if match:
                invalid_user = match.group(1)
                ip = match.group(2)
                invalid_users.append(f"{invalid_user} (from {ip})")
                failed_by_ip[ip] += 1
            
            # 3. sudo failures (privilege escalation attempts)
            if sudo_fail_pattern.search(line):
                sudo_failures += 1
            
            # 4. Successful logins (for comparison)
            match = success_pattern.search(line)
            if match:
                user = match.group(1)
                ip = match.group(2)
                successful_logins.append(f"{user} from {ip}")
    
    # Detect attack patterns
    # Pattern 1: Same IP multiple failures
    for ip, count in failed_by_ip.items():
        if count >= 5:
            attack_patterns.append(f"⚠️ Brute force detected from {ip} ({count} attempts)")
        elif count >= 3:
            attack_patterns.append(f"⚠️ Multiple failures from {ip} ({count} attempts)")
    
    # Pattern 2: Unusual username attempts
    suspicious_users = [u for u in failed_by_user.keys() if u not in ['ubuntu', 'root', 'admin']]
    if suspicious_users:
        attack_patterns.append(f"⚠️ Suspicious usernames attempted: {', '.join(set(suspicious_users))}")
    
    # Generate report
    with open("report.txt", "w") as report:
        report.write("=" * 50 + "\n")
        report.write(" ADVANCED LOG ANALYZER REPORT\n")
        report.write("=" * 50 + "\n\n")
        
        report.write(f"📊 SUMMARY STATISTICS\n")
        report.write(f"   Failed Login Attempts: {failed_logins}\n")
        report.write(f"   Invalid Users Attempted: {len(invalid_users)}\n")
        report.write(f"   Sudo Authentication Failures: {sudo_failures}\n")
        report.write(f"   Successful Logins: {len(successful_logins)}\n\n")
        
        if failed_by_user:
            report.write("👤 FAILED LOGINS BY USERNAME\n")
            for user, count in sorted(failed_by_user.items(), key=lambda x: x[1], reverse=True)[:5]:
                report.write(f"   {user}: {count} times\n")
            report.write("\n")
        
        if failed_by_ip:
            report.write("🌐 FAILED LOGINS BY IP ADDRESS\n")
            for ip, count in sorted(failed_by_ip.items(), key=lambda x: x[1], reverse=True)[:5]:
                report.write(f"   {ip}: {count} attempts\n")
            report.write("\n")
        
        if invalid_users:
            report.write("❌ INVALID USER ATTEMPTS (hacker reconnaissance)\n")
            for inv in invalid_users[:5]:
                report.write(f"   {inv}\n")
            report.write("\n")
        
        if attack_patterns:
            report.write("🚨 SECURITY ALERTS\n")
            for alert in attack_patterns:
                report.write(f"   {alert}\n")
            report.write("\n")
        
        if successful_logins:
            report.write("✅ SUCCESSFUL LOGINS (for reference)\n")
            for succ in successful_logins[-3:]:
                report.write(f"   {succ}\n")
            report.write("\n")
        
        report.write("=" * 50 + "\n")
        report.write(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Console output
    print("\n" + "=" * 50)
    print("🔐 ADVANCED LOG ANALYZER")
    print("=" * 50)
    print(f"✓ Failed Login Attempts: {failed_logins}")
    print(f"✓ Invalid Users: {len(invalid_users)}")
    print(f"✓ Sudo Failures: {sudo_failures}")
    
    if attack_patterns:
        print("\n⚠️  SECURITY ALERTS FOUND!")
        for alert in attack_patterns[:3]:
            print(f"   {alert}")
    
    print("\n✓ Full report saved as report.txt")

except FileNotFoundError:
    print(f"❌ Error: {log_file} not found!")
    print("   This system may not use auth.log (try: /var/log/secure on RHEL)")
except PermissionError:
    print("❌ Error: Permission denied. Run with: sudo python3 analyzer.py")
except Exception as e:
    print(f"❌ Unexpected error: {e}")
