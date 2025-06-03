#!/bin/bash

# Verifica se o comando 'simple_switch_CLI' está disponível
if ! command -v simple_switch_CLI &> /dev/null; then
    echo "Erro: simple_switch_CLI não encontrado. Adicione-o ao PATH ou instale-o."
    exit 1
fi

# Define um array com os pares de porta e ficheiro
declare -a comandos=(
  "9090 flows/s1-flows.txt"
  "9091 flows/r1-flows.txt"
  "9092 flows/r2-flows.txt"
  "9093 flows/r3-flows.txt"
  "9094 flows/r4-flows.txt"
  "9095 flows/r5-flows.txt"
  "9096 flows/r6-flows.txt"
)

# Executa cada comando
for cmd in "${comandos[@]}"; do
  porta=$(echo $cmd | cut -d ' ' -f 1)
  ficheiro=$(echo $cmd | cut -d ' ' -f 2)

  echo "Configurando porta $porta com ficheiro $ficheiro..."
  simple_switch_CLI --thrift-port "$porta" < "$ficheiro"

  if [ $? -ne 0 ]; then
    echo "Erro ao configurar $ficheiro na porta $porta"
    exit 1
  fi
done

echo "Todos os fluxos foram configurados com sucesso."