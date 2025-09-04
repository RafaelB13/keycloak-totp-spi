#!/bin/bash

# Script para adicionar a role manage-totp ao service account

# Configurações
KEYCLOAK_URL="http://localhost:8080/auth"
ADMIN_USER="admin"
ADMIN_PASSWORD="admin"
REALM="masan-local"
CLIENT_ID="masan-api"

echo "🔐 Adicionando role manage-totp ao service account..."

# 1. Obter token admin
echo "1. Obtendo token admin..."
ADMIN_TOKEN=$(curl -s -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=admin-cli&username=$ADMIN_USER&password=$ADMIN_PASSWORD&grant_type=password" | jq -r '.access_token')

if [ "$ADMIN_TOKEN" == "null" ] || [ -z "$ADMIN_TOKEN" ]; then
    echo "❌ Erro ao obter token admin. Verifique as credenciais."
    exit 1
fi

echo "✅ Token admin obtido"

# 2. Verificar se a role manage-totp existe
echo "2. Verificando se a role manage-totp existe..."
ROLE_EXISTS=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM/roles/manage-totp" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -o /dev/null -w "%{http_code}")

if [ "$ROLE_EXISTS" -ne 200 ]; then
    echo "3. Criando role manage-totp..."
    curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM/roles" \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -H "Content-Type: application/json" \
      -d '{
        "name": "manage-totp",
        "description": "Permite gerenciar TOTP via API",
        "composite": false,
        "clientRole": false
      }'
    echo "✅ Role manage-totp criada"
else
    echo "✅ Role manage-totp já existe"
fi

# 4. Obter ID do cliente
echo "4. Obtendo ID do cliente $CLIENT_ID..."
CLIENT=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM/clients?clientId=$CLIENT_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0]')

CLIENT_UUID=$(echo $CLIENT | jq -r '.id')

if [ "$CLIENT_UUID" == "null" ] || [ -z "$CLIENT_UUID" ]; then
    echo "❌ Cliente $CLIENT_ID não encontrado"
    exit 1
fi

echo "✅ ID do cliente: $CLIENT_UUID"

# 5. Obter service account user
echo "5. Obtendo service account user..."
SERVICE_ACCOUNT_USER=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM/clients/$CLIENT_UUID/service-account-user" \
  -H "Authorization: Bearer $ADMIN_TOKEN")

SERVICE_ACCOUNT_ID=$(echo $SERVICE_ACCOUNT_USER | jq -r '.id')

if [ "$SERVICE_ACCOUNT_ID" == "null" ] || [ -z "$SERVICE_ACCOUNT_ID" ]; then
    echo "❌ Service account não encontrado. Verifique se 'Service Accounts Enabled' está ativado no cliente."
    exit 1
fi

echo "✅ Service account ID: $SERVICE_ACCOUNT_ID"

# 6. Obter detalhes da role manage-totp
echo "6. Obtendo detalhes da role manage-totp..."
ROLE=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM/roles/manage-totp" \
  -H "Authorization: Bearer $ADMIN_TOKEN")

# 7. Atribuir role ao service account
echo "7. Atribuindo role manage-totp ao service account..."
curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM/users/$SERVICE_ACCOUNT_ID/role-mappings/realm" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "[$(echo $ROLE | jq -c .)]"

# 8. Verificar roles atribuídas
echo "8. Verificando roles atribuídas..."
ASSIGNED_ROLES=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM/users/$SERVICE_ACCOUNT_ID/role-mappings/realm" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[].name')

echo ""
echo "✅ Roles atribuídas ao service account:"
echo "$ASSIGNED_ROLES"
echo ""

if echo "$ASSIGNED_ROLES" | grep -q "manage-totp"; then
    echo "✅ Role manage-totp atribuída com sucesso!"
    echo ""
    echo "📌 Agora você pode obter um novo token e testar a API:"
    echo ""
    echo "# Obter token:"
    echo "curl -X POST '$KEYCLOAK_URL/realms/$REALM/protocol/openid-connect/token' \\"
    echo "  -H 'Content-Type: application/x-www-form-urlencoded' \\"
    echo "  -d 'client_id=$CLIENT_ID&client_secret=YOUR_SECRET&grant_type=client_credentials'"
else
    echo "❌ Erro ao atribuir role manage-totp"
fi