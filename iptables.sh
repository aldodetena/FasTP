#!/bin/bash

# Añade una regla para redirigir el tráfico del puerto 45000 al puerto 21
sudo iptables -t nat -A PREROUTING -p tcp --dport 45000 -j REDIRECT --to-port 21

# Guarda las reglas para que persistan después de reiniciar
# Esto depende de tu sistema, en algunas distribuciones puede ser diferente
sudo iptables-save > /etc/iptables/rules.v4
