# Open Windows Firewall for honeypot port 2222
# Run this script as Administrator on the DEFENDER machine

netsh advfirewall firewall add rule `
    name="Honeypot SSH Port 2222" `
    dir=in `
    action=allow `
    protocol=TCP `
    localport=2222

Write-Host "[✓] Firewall rule added for port 2222"
Write-Host "Verify with: netsh advfirewall firewall show rule name='Honeypot SSH Port 2222'"
