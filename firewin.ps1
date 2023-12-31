# Crea una nueva regla de redirección de puerto en el firewall
New-NetFirewallRule -DisplayName "Port Redirection 45000 to 21" -Direction Inbound -Protocol TCP -LocalPort 45000 -Action Allow

# Configura la redirección de puerto
netsh interface portproxy add v4tov4 listenport=45000 listenaddress=0.0.0.0 connectport=21 connectaddress=127.0.0.1
