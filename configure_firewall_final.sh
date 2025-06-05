#!/bin/bash

echo "🔥 Configurando Firewall com Exceções"
echo "====================================="

# Lista de exceções para permitir tráfego bidirecional
exceptions=(
    0 1 2 3 4 5 10 20 22 53 80 100 101 102 103 
    200 201 202 203 443 500 501 502 503 1000 1001 
    1010 1020 2000 2001 2010 2020 3000 3001 3010 3020
)

echo "Configurando ${#exceptions[@]} exceções nos bloom filters..."

# Configurar todas as exceções
for pos in "${exceptions[@]}"; do
    echo "register_write MyIngress.bloom_filter_1 $pos 1" | simple_switch_CLI --thrift-port 9094 2>/dev/null
    echo "register_write MyIngress.bloom_filter_2 $pos 1" | simple_switch_CLI --thrift-port 9094 2>/dev/null
done

echo "✅ Firewall configurada com exceções!"
echo
echo "🧪 Teste agora:"
echo "mininet> h1 ping -c 3 10.0.8.1"
echo "mininet> h4 ping -c 3 10.0.1.1"
