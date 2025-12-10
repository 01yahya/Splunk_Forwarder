# Splunk Universal Forwarder 9.1.1 - Auto Installer 
Production-ready automated installer for Splunk UF 9.1.1 with error handling, OS detection, and rollback capabilities.

# 1. Edit configuration variables in the script
nano splunk_uf_installer.sh  
Update: INDEXER_IP, INDEX_NAME

# 2. Make executable and run
chmod +x splunk_uf_installer.sh  
sudo ./splunk_uf_installer.sh

# 3. Verify installation
sudo -u splunkfwd /opt/splunkforwarder/bin/splunk status  
sudo -u splunkfwd /opt/splunkforwarder/bin/splunk list forward-server -auth admin:ChangeMe123

# Configuration
Edit these variables before installation:  
  
INDEXER_IP="192.168.187.246" - Your Splunk Enterprise IP  
INDEX_NAME="os_logs" - Target index name  
DEFAULT_PASSWORD="ChangeMe123" - Change after install  
  
# Requirements
  
Linux 64-bit (Ubuntu, RHEL, CentOS, Rocky, SUSE, etc.)  
Package: splunkforwarder-9.1.1-64e843ea36b1-Linux-x86_64.tgz  
2GB free disk space in /opt  
Root/sudo access  
  
# Features
✅ Automatic OS detection (Ubuntu/Debian vs RHEL/CentOS)  
✅ Pre-flight checks (disk space, package integrity, connectivity)  
✅ Automatic rollback on failure  
✅ Backup of existing installations  
✅ Color-coded output with detailed logging  
✅ SSL support (optional)  
  
# Post-Installation
bash# Check logs  
tail -f /opt/splunkforwarder/var/log/splunk/splunkd.log  
  
# Change password
sudo -u splunkfwd /opt/splunkforwarder/bin/splunk edit user admin -password NewPass -auth admin:ChangeMe123   
  
# Restart
sudo -u splunkfwd /opt/splunkforwarder/bin/splunk restart  
# Troubleshooting  
Connection issues: Verify indexer is listening on port 9997  
Permission errors: Ensure script is run with sudo  
Package not found: Place .tgz file in same directory as script  
Installation log: /var/log/splunk_uf_install.log  
