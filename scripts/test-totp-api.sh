#!/bin/bash

# Script para testar a API TOTP

# Configurações
KEYCLOAK_URL="http://localhost:8080/auth"
REALM="example"
CLIENT_ID="totp-api-client"
CLIENT_SECRET="your-client-secret-here"
TEST_USER_ID=""  # Será preenchido depois

# Cores para output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🔐 Testando TOTP API do Keycloak${NC}"
echo ""

# 1. Obter token do service account
echo -e "${BLUE}1. Obtendo token do service account...${NC}"
TOKEN_RESPONSE=$(curl -s -X POST "$KEYCLOAK_URL/realms/$REALM/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&grant_type=client_credentials")

ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.access_token')

if [ "$ACCESS_TOKEN" == "null" ] || [ -z "$ACCESS_TOKEN" ]; then
    echo -e "${RED}❌ Erro ao obter token${NC}"
    echo "Resposta: $TOKEN_RESPONSE"
    exit 1
fi

echo -e "${GREEN}✅ Token obtido com sucesso${NC}"
echo ""

# 2. Configurar role manage-totp no service account (precisa ser feito via admin)
echo -e "${BLUE}2. Obtendo token admin para configuração...${NC}"
ADMIN_TOKEN=$(curl -s -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=admin-cli&username=admin&password=admin&grant_type=password" | jq -r '.access_token')

if [ "$ADMIN_TOKEN" == "null" ] || [ -z "$ADMIN_TOKEN" ]; then
    echo -e "${RED}❌ Erro ao obter token admin${NC}"
    exit 1
fi

# Obter service account user
SERVICE_ACCOUNT_USER=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM/clients/$CLIENT_ID/service-account-user" \
  -H "Authorization: Bearer $ADMIN_TOKEN")

SERVICE_ACCOUNT_ID=$(echo $SERVICE_ACCOUNT_USER | jq -r '.id')

# Atribuir role manage-totp
curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM/users/$SERVICE_ACCOUNT_ID/role-mappings/realm" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '[{"name": "manage-totp"}]'

echo -e "${GREEN}✅ Role manage-totp atribuída ao service account${NC}"
echo ""

# 3. Obter ID do usuário de teste
echo -e "${BLUE}3. Obtendo ID do usuário de teste...${NC}"
TEST_USER=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM/users?username=testuser" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0]')

TEST_USER_ID=$(echo $TEST_USER | jq -r '.id')

if [ "$TEST_USER_ID" == "null" ] || [ -z "$TEST_USER_ID" ]; then
    echo -e "${RED}❌ Usuário de teste não encontrado${NC}"
    exit 1
fi

echo -e "${GREEN}✅ ID do usuário: $TEST_USER_ID${NC}"
echo ""

# Obter novo token com a role
echo -e "${BLUE}Obtendo novo token com role manage-totp...${NC}"
TOKEN_RESPONSE=$(curl -s -X POST "$KEYCLOAK_URL/realms/$REALM/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&grant_type=client_credentials")

ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.access_token')

# 4. Gerar TOTP
echo -e "${BLUE}4. Gerando TOTP para o usuário...${NC}"
GENERATE_RESPONSE=$(curl -s -X GET "$KEYCLOAK_URL/realms/$REALM/totp-api/$TEST_USER_ID/generate" \
  -H "Authorization: Bearer $ACCESS_TOKEN")

ENCODED_SECRET=$(echo $GENERATE_RESPONSE | jq -r '.encodedSecret')
QR_CODE=$(echo $GENERATE_RESPONSE | jq -r '.qrCode')

if [ "$ENCODED_SECRET" == "null" ] || [ -z "$ENCODED_SECRET" ]; then
    echo -e "${RED}❌ Erro ao gerar TOTP${NC}"
    echo "Resposta: $GENERATE_RESPONSE"
    exit 1
fi

echo -e "${GREEN}✅ TOTP gerado com sucesso${NC}"
echo "   Secret: $ENCODED_SECRET"
echo ""

# 5. Registrar TOTP (simulando código inicial)
echo -e "${BLUE}5. Registrando TOTP...${NC}"
# Nota: Em produção, o código inicial deve ser gerado por um app autenticador
INITIAL_CODE="123456"  # Código de exemplo

REGISTER_RESPONSE=$(curl -s -X POST "$KEYCLOAK_URL/realms/$REALM/totp-api/$TEST_USER_ID/register" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"deviceName\": \"Test Device\",
    \"encodedSecret\": \"$ENCODED_SECRET\",
    \"initialCode\": \"$INITIAL_CODE\",
    \"overwrite\": true
  }")

MESSAGE=$(echo $REGISTER_RESPONSE | jq -r '.message')

if [[ "$MESSAGE" == "TOTP credential registered" ]]; then
    echo -e "${GREEN}✅ TOTP registrado com sucesso${NC}"
else
    echo -e "${RED}❌ Erro ao registrar TOTP${NC}"
    echo "Resposta: $REGISTER_RESPONSE"
fi
echo ""

# 6. Verificar TOTP
echo -e "${BLUE}6. Verificando TOTP...${NC}"
VERIFY_RESPONSE=$(curl -s -X POST "$KEYCLOAK_URL/realms/$REALM/totp-api/$TEST_USER_ID/verify" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"deviceName\": \"Test Device\",
    \"code\": \"123456\"
  }")

VERIFY_MESSAGE=$(echo $VERIFY_RESPONSE | jq -r '.message')
echo "Resposta: $VERIFY_MESSAGE"
echo ""

echo -e "${BLUE}📊 Resumo dos endpoints testados:${NC}"
echo "   - GET  /realms/$REALM/totp-api/{userId}/generate"
echo "   - POST /realms/$REALM/totp-api/{userId}/register"
echo "   - POST /realms/$REALM/totp-api/{userId}/verify"
echo ""
echo -e "${GREEN}✅ Teste concluído!${NC}"