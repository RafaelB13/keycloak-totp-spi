#!/bin/bash

# Script para configurar Keycloak com TOTP API

echo "🚀 Iniciando setup do Keycloak com TOTP API..."

# Verificar se o JAR existe
if [ ! -f "build/libs/keycloak-totp-spi.jar" ]; then
    echo "❌ JAR não encontrado. Executando build..."
    ./gradlew clean shadowJar
    if [ $? -ne 0 ]; then
        echo "❌ Erro ao compilar o projeto"
        exit 1
    fi
fi

echo "✅ JAR encontrado"

# Parar containers existentes
echo "🛑 Parando containers existentes..."
docker-compose -f docker-compose-dev.yml down -v

# Iniciar containers
echo "🚀 Iniciando containers..."
docker-compose -f docker-compose-dev.yml up -d

# Aguardar Keycloak inicializar
echo "⏳ Aguardando Keycloak inicializar (pode levar até 2 minutos)..."
sleep 10

# Verificar se está rodando
max_attempts=30
attempt=0

while [ $attempt -lt $max_attempts ]; do
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/auth/ | grep -q "200\|302"; then
        echo "✅ Keycloak está rodando!"
        break
    fi
    echo "⏳ Aguardando... ($((attempt+1))/$max_attempts)"
    sleep 5
    attempt=$((attempt+1))
done

if [ $attempt -eq $max_attempts ]; then
    echo "❌ Timeout ao aguardar Keycloak inicializar"
    echo "📋 Logs do container:"
    docker logs keycloak --tail 50
    exit 1
fi

echo ""
echo "✅ Setup completo!"
echo ""
echo "📌 URLs importantes:"
echo "   - Keycloak Admin: http://localhost:8080/auth/"
echo "   - Credenciais: admin / admin"
echo ""
echo "📌 Realm de exemplo:"
echo "   - Nome: example"
echo "   - Cliente: totp-api-client"
echo "   - Secret: your-client-secret-here"
echo ""
echo "📌 Para obter o token do service account:"
echo "   curl -X POST 'http://localhost:8080/auth/realms/example/protocol/openid-connect/token' \\"
echo "   -H 'Content-Type: application/x-www-form-urlencoded' \\"
echo "   -d 'client_id=totp-api-client&client_secret=your-client-secret-here&grant_type=client_credentials'"
echo ""
echo "📌 Para ver os logs:"
echo "   docker-compose -f docker-compose-dev.yml logs -f keycloak"