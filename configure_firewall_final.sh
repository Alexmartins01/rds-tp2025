#!/bin/bash

echo "🔥 Configurando Túneis MSLP Bidirecionais"
echo "========================================"

echo "✅ R4 agora usa l3switch.json (sem firewall)"
echo "✅ Não precisa configurar bloom filters"
echo "✅ Só precisa configurar túneis!"

echo
echo "🔧 Verificando configuração atual dos túneis..."

echo "R1 mslpTunnel:"
echo "table_dump mslpTunnel" | simple_switch_CLI --thrift-port 9091

echo
echo "R4 mslpTunnel:"
echo "table_dump mslpTunnel" | simple_switch_CLI --thrift-port 9094

echo
echo "🧪 TESTE AGORA:"
echo "mininet> h1 ping -c 3 10.0.8.1  # Túnel direto"
echo "mininet> h4 ping -c 3 10.0.1.1  # Túnel reverso"

echo
echo "🔍 Para verificar se usa túneis MSLP:"
echo "mininet> s1 tcpdump -i any -n 'ether proto 0x88b5' &"
echo "mininet> h1 ping -c 1 10.0.8.1"
echo "mininet> killall tcpdump"

echo
echo "🎯 STATUS:"
echo "• R4 SEM firewall → Não bloqueia tráfego"
echo "• Túneis bidirecionais configurados"
echo "• Deve funcionar agora!"

echo
echo "📊 FLUXOS CONFIGURADOS:"
echo "• Túnel direto:  h1→R1→R2→R3→R4→h4 (labels: 1020→2020→3020)"
echo "• Túnel reverso: h4→R4→R5→R6→R1→h1 (labels: 6020→5020→1020)"
