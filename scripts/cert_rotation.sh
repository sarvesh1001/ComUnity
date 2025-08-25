#!/bin/bash
# Production Certificate Rotation Script
set -euo pipefail
shopt -s nullglob

# Configuration
CERT_DIR="/etc/authservice/certs"
BACKUP_DIR="/etc/authservice/certs/backups"
TEMP_DIR=$(mktemp -d)
LOG_FILE="/var/log/cert_rotation.log"
EMAIL="security-alerts@example.com"
CERT_PREFIX="authservice-cert"
KEY_PREFIX="authservice-key"
KMS_KEY_ID="alias/authservice-kms-key"

# Initialize logging
exec &> >(tee -a "$LOG_FILE")

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

notify() {
    local subject="Certificate Rotation Alert: $1"
    local message="$2"
    echo "$message" | mail -s "$subject" "$EMAIL"
    log "Notification sent: $subject"
}

# Create required directories
mkdir -p {"$CERT_DIR","$BACKUP_DIR","$TEMP_DIR"}

# Generate new certificate
log "Generating new certificate..."
openssl req -x509 -newkey rsa:4096 -sha256 -days 90 -nodes \
    -keyout "$TEMP_DIR/$KEY_PREFIX-$(date +%Y%m%d).pem" \
    -out "$TEMP_DIR/$CERT_PREFIX-$(date +%Y%m%d).pem" \
    -subj "/CN=authservice.example.com/O=Company/C=IN" \
    -addext "subjectAltName=DNS:authservice.example.com,DNS:*.authservice.example.com" \
    -addext "keyUsage=digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" \
    -addext "basicConstraints=CA:FALSE"

# Encrypt with KMS
log "Encrypting certificate with KMS..."
aws kms encrypt --key-id "$KMS_KEY_ID" \
    --plaintext "fileb://$TEMP_DIR/$CERT_PREFIX-$(date +%Y%m%d).pem" \
    --output text --query CiphertextBlob | base64 --decode \
    > "$TEMP_DIR/$CERT_PREFIX-$(date +%Y%m%d).enc"

aws kms encrypt --key-id "$KMS_KEY_ID" \
    --plaintext "fileb://$TEMP_DIR/$KEY_PREFIX-$(date +%Y%m%d).pem" \
    --output text --query CiphertextBlob | base64 --decode \
    > "$TEMP_DIR/$KEY_PREFIX-$(date +%Y%m%d).enc"

# Backup current certificates
log "Backing up current certificates..."
cp "$CERT_DIR/$CERT_PREFIX"* "$BACKUP_DIR/" || true
cp "$CERT_DIR/$KEY_PREFIX"* "$BACKUP_DIR/" || true

# Rotate certificates
log "Rotating certificates..."
mv "$TEMP_DIR/$CERT_PREFIX-$(date +%Y%m%d).enc" "$CERT_DIR/"
mv "$TEMP_DIR/$KEY_PREFIX-$(date +%Y%m%d).enc" "$CERT_DIR/"

# Update symlinks
ln -sf "$CERT_DIR/$CERT_PREFIX-$(date +%Y%m%d).enc" "$CERT_DIR/current-cert.enc"
ln -sf "$CERT_DIR/$KEY_PREFIX-$(date +%Y%m%d).enc" "$CERT_DIR/current-key.enc"

# Reload services
log "Reloading services..."
systemctl reload nginx || true
systemctl reload authservice || true

# Clean up
rm -rf "$TEMP_DIR"
log "Certificate rotation completed successfully"

# Update SSM parameter with new expiration date
NEW_EXPIRY=$(date -d "+90 days" "+%Y-%m-%d")
aws ssm put-parameter --name "/authservice/cert_expiry" \
    --value "$NEW_EXPIRY" --type "String" --overwrite

exit 0