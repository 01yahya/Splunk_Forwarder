#!/bin/bash
################################################################################
# Splunk Universal Forwarder 9.1.1 - Complete Auto Installer
# Description: Production-ready installer with comprehensive error handling,
#              OS detection, logging, and rollback capabilities
################################################################################

set -euo pipefail  # Exit on error, undefined variables, pipe failures

# ====================== CONFIGURATION VARIABLES ==============================
SPLUNK_HOME="/opt/splunkforwarder"
UF_PACKAGE="splunkforwarder-9.1.1-64e843ea36b1-Linux-x86_64.tgz"
INDEXER_IP="192.168.186.246"         # Your Splunk Enterprise IP
INDEXER_PORT="9997"                  # Receiving port
INDEX_NAME="os_logs"                 # Target index name
SPLUNK_USER="splunkfwd"
SPLUNK_GROUP="splunkfwd"
DEPLOYMENT_SERVER=""                 # Optional: DS IP:port
DEFAULT_PASSWORD="ChangeMe123"       # Default admin password
LOG_FILE="/var/log/splunk_uf_install.log"
BACKUP_DIR="/opt/splunk_backup_$(date +%Y%m%d_%H%M%S)"

# SSL Configuration (set to true to enable)
USE_SSL="false"
SSL_CERT_PATH=""                     # Path to server certificate
SSL_ROOT_CA_PATH=""                  # Path to CA certificate

# ====================== COLOR CODES ==========================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ====================== LOGGING FUNCTIONS ====================================
setup_logging() {
    exec > >(tee -a "$LOG_FILE")
    exec 2>&1
    log_info "Installation log: $LOG_FILE"
}

log_info() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} ${CYAN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} ${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} ${RED}[ERROR]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS]${NC} $1"
}

print_banner() {
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║        Splunk Universal Forwarder 9.1.1 Installer             ║"
    echo "║                    Version 2.0                                 ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ====================== CLEANUP AND ROLLBACK =================================
cleanup_on_error() {
    log_error "Installation failed! Initiating cleanup..."
    
    # Stop Splunk if running
    if [ -f "$SPLUNK_HOME/bin/splunk" ]; then
        log_info "Stopping Splunk UF..."
        $SPLUNK_HOME/bin/splunk stop 2>/dev/null || true
    fi
    
    # Remove installation directory
    if [ -d "$SPLUNK_HOME" ]; then
        log_warn "Removing $SPLUNK_HOME"
        rm -rf "$SPLUNK_HOME"
    fi
    
    # Remove user
    if id "$SPLUNK_USER" &>/dev/null; then
        log_warn "Removing user $SPLUNK_USER"
        userdel -r "$SPLUNK_USER" 2>/dev/null || true
    fi
    
    # Remove boot-start script
    if [ -f "/etc/init.d/splunk" ]; then
        rm -f /etc/init.d/splunk
    fi
    
    log_error "Installation rolled back. Check log: $LOG_FILE"
    exit 1
}

backup_existing_installation() {
    if [ -d "$SPLUNK_HOME" ]; then
        log_info "Backing up existing installation to $BACKUP_DIR"
        mkdir -p "$BACKUP_DIR"
        cp -r "$SPLUNK_HOME" "$BACKUP_DIR/"
        log_success "Backup completed"
    fi
}

# Set trap for cleanup
trap cleanup_on_error ERR

# ====================== PRE-FLIGHT CHECKS ====================================
preflight_checks() {
    log_info "Running pre-flight checks..."
    
    # Check root privileges
    if [ "$EUID" -ne 0 ]; then 
        log_error "This script must be run as root or with sudo"
        exit 1
    fi
    
    # Check if package exists
    if [ ! -f "$UF_PACKAGE" ]; then
        log_error "Installation package not found: $UF_PACKAGE"
        log_error "Please ensure the package is in the current directory"
        exit 1
    fi
    
    # Verify package integrity
    log_info "Verifying package integrity..."
    if ! tar -tzf "$UF_PACKAGE" > /dev/null 2>&1; then
        log_error "Package appears to be corrupted: $UF_PACKAGE"
        exit 1
    fi
    
    # Check disk space (minimum 2GB)
    available_space=$(df /opt | awk 'NR==2 {print $4}')
    if [ "$available_space" -lt 2097152 ]; then
        log_error "Insufficient disk space. At least 2GB required in /opt"
        exit 1
    fi
    
    # Check if required ports are available
    if netstat -tuln 2>/dev/null | grep -q ":8089 "; then
        log_warn "Port 8089 is already in use (Splunk Enterprise might be installed)"
    fi
    
    # Validate IP address format
    if [[ ! $INDEXER_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        log_error "Invalid indexer IP address format: $INDEXER_IP"
        exit 1
    fi
    
    log_success "Pre-flight checks passed"
}

# ====================== OS DETECTION =========================================
detect_os() {
    log_info "Detecting operating system..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID=$ID
        OS_VERSION=$VERSION_ID
        OS_NAME=$PRETTY_NAME
    elif [ -f /etc/redhat-release ]; then
        OS_ID="rhel"
        OS_NAME=$(cat /etc/redhat-release)
    else
        log_warn "Cannot detect OS, assuming Ubuntu/Debian"
        OS_ID="ubuntu"
        OS_NAME="Unknown Linux"
    fi
    
    log_info "Detected: $OS_NAME"
    
    # Set OS-specific variables
    case $OS_ID in
        ubuntu|debian)
            LOG_AUTH="/var/log/auth.log"
            LOG_SYSLOG="/var/log/syslog"
            LOG_MESSAGES=""
            LOG_SECURE=""
            ;;
        rhel|centos|rocky|almalinux)
            LOG_AUTH=""
            LOG_SYSLOG=""
            LOG_MESSAGES="/var/log/messages"
            LOG_SECURE="/var/log/secure"
            ;;
        *)
            log_warn "Unknown OS, using generic configuration"
            LOG_SYSLOG="/var/log/syslog"
            LOG_AUTH="/var/log/auth.log"
            ;;
    esac
}

# ====================== EXISTING INSTALLATION CHECK ==========================
check_existing_installation() {
    if [ -d "$SPLUNK_HOME" ]; then
        log_warn "Splunk UF is already installed at $SPLUNK_HOME"
        echo ""
        echo -e "${YELLOW}Options:${NC}"
        echo "  1) Reinstall (removes existing installation)"
        echo "  2) Upgrade (preserves configuration)"
        echo "  3) Cancel installation"
        echo ""
        read -p "Select option [1-3]: " -r choice
        
        case $choice in
            1)
                log_info "User selected: Reinstall"
                backup_existing_installation
                log_info "Stopping existing installation..."
                $SPLUNK_HOME/bin/splunk stop 2>/dev/null || true
                log_info "Removing existing installation..."
                rm -rf "$SPLUNK_HOME"
                ;;
            2)
                log_info "User selected: Upgrade"
                backup_existing_installation
                log_info "Stopping existing installation..."
                $SPLUNK_HOME/bin/splunk stop 2>/dev/null || true
                UPGRADE_MODE=true
                ;;
            3)
                log_info "Installation cancelled by user"
                exit 0
                ;;
            *)
                log_error "Invalid option"
                exit 1
                ;;
        esac
    fi
}

# ====================== USER CREATION ========================================
create_splunk_user() {
    log_info "Setting up Splunk user account..."
    
    if id "$SPLUNK_USER" &>/dev/null; then
        log_info "User $SPLUNK_USER already exists"
    else
        log_info "Creating user: $SPLUNK_USER"
        useradd -r -m -d /home/$SPLUNK_USER -s /bin/bash "$SPLUNK_USER"
        
        # Set password expiry to never
        chage -I -1 -m 0 -M 99999 -E -1 "$SPLUNK_USER" 2>/dev/null || true
        
        log_success "User $SPLUNK_USER created"
    fi
}

# ====================== INSTALLATION =========================================
install_splunk_uf() {
    log_info "Beginning Splunk UF installation..."
    
    # Extract package
    log_info "Extracting package to /opt (this may take a moment)..."
    tar -xzf "$UF_PACKAGE" -C /opt
    
    if [ ! -d "$SPLUNK_HOME" ]; then
        log_error "Extraction failed - directory not created"
        exit 1
    fi
    
    log_success "Package extracted successfully"
    
    # Set ownership and permissions
    log_info "Setting ownership and permissions..."
    chown -R $SPLUNK_USER:$SPLUNK_GROUP "$SPLUNK_HOME"
    chmod -R 755 "$SPLUNK_HOME"
    
    # Secure sensitive directories (if they exist)
    if [ -d "$SPLUNK_HOME/etc/auth" ]; then
        chmod 700 "$SPLUNK_HOME/etc/auth"
    fi
    
    if [ -d "$SPLUNK_HOME/var" ]; then
        chmod 700 "$SPLUNK_HOME/var"
    fi
    
    log_success "Permissions set"
}

# ====================== CONFIGURATION FILES ==================================
create_inputs_conf() {
    log_info "Creating inputs.conf..."
    
    local conf_file="$SPLUNK_HOME/etc/system/local/inputs.conf"
    
    cat > "$conf_file" << 'EOF'
# Splunk Universal Forwarder - Input Configuration
# Auto-generated by installer

[default]
host = $decideOnStartup

EOF

    # Add OS-specific monitors
    if [ -n "$LOG_SYSLOG" ] && [ -f "$LOG_SYSLOG" ]; then
        cat >> "$conf_file" << EOF
[monitor://$LOG_SYSLOG]
index = $INDEX_NAME
sourcetype = linux:syslog
disabled = false

EOF
    fi
    
    if [ -n "$LOG_AUTH" ] && [ -f "$LOG_AUTH" ]; then
        cat >> "$conf_file" << EOF
[monitor://$LOG_AUTH]
index = $INDEX_NAME
sourcetype = linux:auth
disabled = false

EOF
    fi
    
    if [ -n "$LOG_MESSAGES" ] && [ -f "$LOG_MESSAGES" ]; then
        cat >> "$conf_file" << EOF
[monitor://$LOG_MESSAGES]
index = $INDEX_NAME
sourcetype = linux:messages
disabled = false

EOF
    fi
    
    if [ -n "$LOG_SECURE" ] && [ -f "$LOG_SECURE" ]; then
        cat >> "$conf_file" << EOF
[monitor://$LOG_SECURE]
index = $INDEX_NAME
sourcetype = linux:secure
disabled = false

EOF
    fi
    
    # Add general log monitoring with exclusions
    cat >> "$conf_file" << EOF
# Generic log monitoring with blacklist
[monitor:///var/log]
index = $INDEX_NAME
sourcetype = linux:syslog
blacklist = \.(gz|bz2|z|zip|rar|tar|7z|iso|dmg|exe|dll|bin|dat|db|old|log\.[0-9]+)$
disabled = false

# Common application logs
[monitor:///var/log/apache2/*.log]
index = $INDEX_NAME
sourcetype = apache:access
disabled = false

[monitor:///var/log/nginx/*.log]
index = $INDEX_NAME
sourcetype = nginx:access
disabled = false
EOF
    
    chmod 600 "$conf_file"
    chown $SPLUNK_USER:$SPLUNK_GROUP "$conf_file"
    
    log_success "inputs.conf created"
}

create_outputs_conf() {
    log_info "Creating outputs.conf..."
    
    local conf_file="$SPLUNK_HOME/etc/system/local/outputs.conf"
    
    cat > "$conf_file" << EOF
# Splunk Universal Forwarder - Output Configuration
# Auto-generated by installer

[tcpout]
defaultGroup = primary_indexers
compressed = true
connectionTimeout = 20
readTimeout = 300
writeTimeout = 300

[tcpout:primary_indexers]
server = $INDEXER_IP:$INDEXER_PORT
autoLB = true
useACK = true
maxQueueSize = 7MB

EOF

    # Add SSL configuration if enabled
    if [ "$USE_SSL" = "true" ] && [ -n "$SSL_CERT_PATH" ] && [ -n "$SSL_ROOT_CA_PATH" ]; then
        cat >> "$conf_file" << EOF
# SSL Configuration
sslCertPath = $SSL_CERT_PATH
sslRootCAPath = $SSL_ROOT_CA_PATH
sslVerifyServerCert = true
sslCommonNameToCheck = $INDEXER_IP

EOF
        log_info "SSL configuration added"
    fi
    
    chmod 600 "$conf_file"
    chown $SPLUNK_USER:$SPLUNK_GROUP "$conf_file"
    
    log_success "outputs.conf created"
}

create_deploymentclient_conf() {
    if [ -n "$DEPLOYMENT_SERVER" ]; then
        log_info "Creating deploymentclient.conf..."
        
        local conf_file="$SPLUNK_HOME/etc/system/local/deploymentclient.conf"
        
        cat > "$conf_file" << EOF
# Deployment Server Configuration

[deployment-client]

[target-broker:deploymentServer]
targetUri = $DEPLOYMENT_SERVER
EOF
        
        chmod 600 "$conf_file"
        chown $SPLUNK_USER:$SPLUNK_GROUP "$conf_file"
        
        log_success "deploymentclient.conf created"
    fi
}

create_server_conf() {
    log_info "Creating server.conf..."
    
    local conf_file="$SPLUNK_HOME/etc/system/local/server.conf"
    
    cat > "$conf_file" << EOF
# Server Configuration

[general]
serverName = $(hostname)
pass4SymmKey = \$7\$changeme

[sslConfig]
enableSplunkdSSL = true
EOF
    
    chmod 600 "$conf_file"
    chown $SPLUNK_USER:$SPLUNK_GROUP "$conf_file"
    
    log_success "server.conf created"
}

configure_splunk() {
    log_info "Configuring Splunk UF..."
    
    mkdir -p "$SPLUNK_HOME/etc/system/local"
    
    create_inputs_conf
    create_outputs_conf
    create_deploymentclient_conf
    create_server_conf
    
    # Set proper ownership for entire etc directory
    chown -R $SPLUNK_USER:$SPLUNK_GROUP "$SPLUNK_HOME/etc"
    
    log_success "Configuration complete"
}

# ====================== START SPLUNK =========================================
start_splunk() {
    log_info "Starting Splunk Universal Forwarder..."
    
    # First start with license acceptance
    sudo -u $SPLUNK_USER $SPLUNK_HOME/bin/splunk start \
        --accept-license \
        --answer-yes \
        --no-prompt \
        --seed-passwd "$DEFAULT_PASSWORD" 2>&1 | tee -a "$LOG_FILE"
    
    # Wait for splunkd to fully start
    log_info "Waiting for splunkd to initialize..."
    sleep 10
    
    # Verify it's running
    if sudo -u $SPLUNK_USER $SPLUNK_HOME/bin/splunk status | grep -q "splunkd is running"; then
        log_success "Splunk UF started successfully"
    else
        log_error "Splunk UF failed to start"
        log_info "Check logs at: $SPLUNK_HOME/var/log/splunk/splunkd.log"
        exit 1
    fi
}

# ====================== ENABLE BOOT START ====================================
enable_boot_start() {
    log_info "Enabling boot-start..."
    
    $SPLUNK_HOME/bin/splunk enable boot-start \
        -user $SPLUNK_USER \
        --accept-license \
        --answer-yes \
        --no-prompt
    
    # Verify init script was created
    if [ -f "/etc/init.d/splunk" ] || [ -f "/etc/systemd/system/Splunkd.service" ]; then
        log_success "Boot-start enabled"
    else
        log_warn "Boot-start may not have been configured properly"
    fi
}

# ====================== POST-INSTALL VERIFICATION ============================
verify_installation() {
    log_info "Verifying installation..."
    
    local errors=0
    
    # Check if splunkd is running
    if ! sudo -u $SPLUNK_USER $SPLUNK_HOME/bin/splunk status | grep -q "splunkd is running"; then
        log_error "splunkd is not running"
        ((errors++))
    else
        log_success "✓ splunkd is running"
    fi
    
    # Check if configs are loaded
    if [ -f "$SPLUNK_HOME/etc/system/local/inputs.conf" ]; then
        log_success "✓ inputs.conf exists"
    else
        log_error "✗ inputs.conf not found"
        ((errors++))
    fi
    
    if [ -f "$SPLUNK_HOME/etc/system/local/outputs.conf" ]; then
        log_success "✓ outputs.conf exists"
    else
        log_error "✗ outputs.conf not found"
        ((errors++))
    fi
    
    # Check connection to indexer
    log_info "Testing connection to indexer at $INDEXER_IP:$INDEXER_PORT..."
    if timeout 5 bash -c "cat < /dev/null > /dev/tcp/$INDEXER_IP/$INDEXER_PORT" 2>/dev/null; then
        log_success "✓ Connection to indexer successful"
    else
        log_warn "✗ Cannot connect to indexer at $INDEXER_IP:$INDEXER_PORT"
        log_warn "  Please verify:"
        log_warn "  - Splunk Enterprise is running on $INDEXER_IP"
        log_warn "  - Receiving is enabled: sudo -u splunk /opt/splunk/bin/splunk enable listen $INDEXER_PORT"
        log_warn "  - Firewall allows connections on port $INDEXER_PORT"
    fi
    
    # Check for errors in splunkd.log
    if grep -i "error\|fatal" "$SPLUNK_HOME/var/log/splunk/splunkd.log" | tail -5 | grep -v "INFO"; then
        log_warn "Recent errors found in splunkd.log"
    fi
    
    if [ $errors -gt 0 ]; then
        log_warn "Installation completed with $errors warnings"
    else
        log_success "All verification checks passed"
    fi
}

# ====================== PRINT SUMMARY ========================================
print_summary() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}              ${GREEN}Installation Complete Successfully!${NC}              ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Installation Details:${NC}"
    echo "  • Splunk Home:       $SPLUNK_HOME"
    echo "  • User:              $SPLUNK_USER"
    echo "  • Indexer:           $INDEXER_IP:$INDEXER_PORT"
    echo "  • Index:             $INDEX_NAME"
    echo "  • OS Detected:       $OS_NAME"
    echo "  • Default Password:  $DEFAULT_PASSWORD"
    echo "  • Installation Log:  $LOG_FILE"
    if [ -d "$BACKUP_DIR" ]; then
        echo "  • Backup Location:   $BACKUP_DIR"
    fi
    echo ""
    echo -e "${BLUE}Useful Commands:${NC}"
    echo "  • Check status:"
    echo "    sudo -u $SPLUNK_USER $SPLUNK_HOME/bin/splunk status"
    echo ""
    echo "  • Restart forwarder:"
    echo "    sudo -u $SPLUNK_USER $SPLUNK_HOME/bin/splunk restart"
    echo ""
    echo "  • View logs:"
    echo "    tail -f $SPLUNK_HOME/var/log/splunk/splunkd.log"
    echo ""
    echo "  • List forwarding status:"
    echo "    sudo -u $SPLUNK_USER $SPLUNK_HOME/bin/splunk list forward-server -auth admin:$DEFAULT_PASSWORD"
    echo ""
    echo "  • Change admin password:"
    echo "    sudo -u $SPLUNK_USER $SPLUNK_HOME/bin/splunk edit user admin -password <new_password> -auth admin:$DEFAULT_PASSWORD"
    echo ""
    echo -e "${YELLOW}⚠ IMPORTANT NEXT STEPS:${NC}"
    echo "  1. Make sure Splunk Enterprise is running on $INDEXER_IP"
    echo "  2. Enable receiving on Enterprise: "
    echo "     sudo -u splunk /opt/splunk/bin/splunk enable listen $INDEXER_PORT -auth admin:password"
    echo "  3. Create the index '$INDEX_NAME' on Enterprise:"
    echo "     sudo -u splunk /opt/splunk/bin/splunk add index $INDEX_NAME -auth admin:password"
    echo "  4. Change the default admin password"
    echo "  5. Check data is flowing in Splunk Web: index=$INDEX_NAME"
    echo ""
    echo -e "${GREEN}For support and documentation, visit:${NC}"
    echo "  https://docs.splunk.com/Documentation/Forwarder"
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
}

# ====================== MAIN EXECUTION =======================================
main() {
    print_banner
    setup_logging
    
    log_info "Installation started at $(date)"
    log_info "Running on: $(hostname)"
    
    # Execute installation steps
    preflight_checks
    detect_os
    check_existing_installation
    create_splunk_user
    install_splunk_uf
    configure_splunk
    start_splunk
    enable_boot_start
    verify_installation
    
    # Print summary
    print_summary
    
    log_success "Installation completed at $(date)"
}

# Execute main function
main "$@"