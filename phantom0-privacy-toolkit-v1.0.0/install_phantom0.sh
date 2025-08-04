#!/bin/bash
# === install_phantom0.sh ===
# Installer for Phantom-0 Privacy Toolkit

set -euo pipefail

INSTALL_DIR="/usr/local/bin/phantom0"
MODULES_DIR="$INSTALL_DIR/modules"
SCRIPT_PATH="$INSTALL_DIR/phantom0.sh"
STARTUP_SERVICE="/etc/systemd/system/phantom0.service"
SHUTDOWN_SERVICE="/etc/systemd/system/phantom0-shutdown.service"

echo "🔐 Installing Phantom-0 Privacy Toolkit..."

# Create install and modules directories
mkdir -p "$INSTALL_DIR"
mkdir -p "$MODULES_DIR"

# Copy main launcher
cp ./phantom0.sh "$SCRIPT_PATH"
chmod +x "$SCRIPT_PATH"
echo "✅ Copied phantom0.sh to $SCRIPT_PATH"

# Copy startup and shutdown routines to modules dir
cp ./modules/PHANTOM0_startup_routine.sh "$MODULES_DIR/"
cp ./modules/PHANTOM0_shutdown_routine.sh "$MODULES_DIR/"
chmod +x "$MODULES_DIR/"*.sh
echo "✅ Copied startup/shutdown modules to $MODULES_DIR"

# Create startup systemd service
cat > "$STARTUP_SERVICE" <<EOF
[Unit]
Description=Phantom-0 Cloak Startup Routine
After=network.target

[Service]
Type=oneshot
ExecStart=$SCRIPT_PATH run PHANTOM0_startup
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

echo "✅ Created systemd startup service at: $STARTUP_SERVICE"

# Prompt for optional shutdown service
read -rp "Would you like to install and enable the Phantom-0 shutdown service? (y/n): " install_shutdown

if [[ "$install_shutdown" =~ ^[Yy]$ ]]; then
  cat > "$SHUTDOWN_SERVICE" <<EOF
[Unit]
Description=Phantom-0 Cloak Shutdown Routine
DefaultDependencies=no
Before=shutdown.target reboot.target halt.target
Requires=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=$SCRIPT_PATH run PHANTOM0_shutdown
TimeoutSec=300
RemainAfterExit=yes

[Install]
WantedBy=halt.target reboot.target shutdown.target
EOF

  echo "✅ Created systemd shutdown service at: $SHUTDOWN_SERVICE"
else
  echo "⚠️  Skipping shutdown service installation."
fi

# Final systemd setup
echo "🔄 Reloading systemd and enabling services..."
systemctl daemon-reload
systemctl enable phantom0.service

if [[ "$install_shutdown" =~ ^[Yy]$ ]]; then
  systemctl enable phantom0-shutdown.service
fi

echo ""
echo "✅ Installation complete!"
echo "• Startup script enabled: phantom0.service"
[[ "$install_shutdown" =~ ^[Yy]$ ]] && echo "• Shutdown script enabled: phantom0-shutdown.service"
echo ""
echo "▶ You can manually start it anytime with:"
echo "   sudo systemctl start phantom0.service"
