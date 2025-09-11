# 🔐 Keycloak TOTP SPI Extension

<div align="center">

[![Keycloak](https://img.shields.io/badge/Keycloak-16.1.1+-blue.svg)](https://www.keycloak.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-11+-orange.svg)](https://www.java.com/)
[![Kotlin](https://img.shields.io/badge/Kotlin-1.8.22-purple.svg)](https://kotlinlang.org/)

**A powerful Keycloak extension that enables TOTP (Time-Based One-Time Password) management via REST API**

[Features](#-features) • [Installation](#-installation) • [API Reference](#-api-reference) • [Authentication](#-authentication)

</div>

---

## 🎯 Features

<table>
<tr>
<td>

### 🔑 Core Capabilities
- **Generate TOTP secrets** with QR code
- **Register TOTP credentials** for users
- **Verify TOTP codes** with flexible device support
- **Manage multiple devices** per user
- **Service account authentication**

</td>
<td>

### 🚀 Key Benefits
- **RESTful API** for programmatic access
- **Multi-device support** with device tracking
- **Flexible verification** (device-specific or any)
- **Clean JSON responses**
- **Production-ready** error handling

</td>
</tr>
</table>

## 📋 Requirements

- **Keycloak**: Version 16.1.1 (tested) or higher
- **Java**: JDK 11 or higher
- **Gradle**: For building from source

## 🛠️ Installation

### 📦 Download Pre-built Release

1. Visit the [Releases](https://github.com/rafaelb13/keycloak-totp-spi/releases) page
2. Download the latest `keycloak-totp-spi.jar` (includes all dependencies)

### 🔨 Build from Source

```bash
# Clone the repository
git clone https://github.com/rafaelb13/keycloak-totp-spi.git
cd keycloak-totp-spi

# Build with Gradle
./gradlew shadowJar

# Find the JAR in build/libs/
```

### 🚀 Deploy to Keycloak

<details>
<summary><b>Standalone Installation</b></summary>

1. Copy the JAR to Keycloak's providers directory:
   ```bash
   cp keycloak-totp-spi.jar ${KEYCLOAK_HOME}/providers/
   ```

2. Build Keycloak with the new extension:
   ```bash
   ${KEYCLOAK_HOME}/bin/kc.sh build
   ```

3. Start Keycloak:
   ```bash
   ${KEYCLOAK_HOME}/bin/kc.sh start
   ```
</details>

<details>
<summary><b>Docker Installation</b></summary>

#### Option 1: Volume Mount
```yaml
services:
  keycloak:
    image: quay.io/keycloak/keycloak:latest
    volumes:
      - ./keycloak-totp-spi-1.0.0-all.jar:/opt/keycloak/providers/keycloak-totp-spi-1.0.0-all.jar
    command: ["start-dev"]
```

#### Option 2: Custom Docker Image
```dockerfile
FROM quay.io/keycloak/keycloak:latest
COPY keycloak-totp-spi.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build
```
</details>

## 📡 API Reference

### Base URL
```
{{KEYCLOAK_URL}}/realms/{{REALM}}/totp-api
```

### 🔍 API Endpoints

<details>
<summary><b>📱 Generate TOTP Secret</b></summary>

Generate a new TOTP secret and QR code for user registration.

```http
GET /{{USER_ID}}/generate
Authorization: Bearer {{TOKEN}}
```

**Response:**
```json
{
  "encodedSecret": "OFIWESBQGBLFG432HB5G6TTLIVIEGU2O",
  "qrCode": "data:image/png;base64,iVBORw0KGgoAAAANS..."
}
```

- `encodedSecret`: Base32-encoded secret for manual entry
- `qrCode`: Base64-encoded PNG image for QR scanning
</details>

<details>
<summary><b>➕ Register TOTP Credential</b></summary>

Register a TOTP credential for a user after verification.

```http
POST /{{USER_ID}}/register
Authorization: Bearer {{TOKEN}}
Content-Type: application/json

{
  "deviceName": "iPhone 15 Pro",
  "encodedSecret": "OFIWESBQGBLFG432HB5G6TTLIVIEGU2O",
  "initialCode": "123456",
  "overwrite": false
}
```

**Parameters:**
- `deviceName`: Friendly name for the device
- `encodedSecret`: The Base32-encoded secret
- `initialCode`: Current TOTP code for verification
- `overwrite`: If `true`, replaces existing credential with same device name

**Response:**
```json
{
  "message": "TOTP credential registered"
}
```
</details>

<details>
<summary><b>✅ Verify TOTP Code</b></summary>

Verify a TOTP code for authentication.

```http
POST /{{USER_ID}}/verify
Authorization: Bearer {{TOKEN}}
Content-Type: application/json

{
  "deviceName": "iPhone 15 Pro",  // Optional
  "code": "123456"
}
```

**Flexible Verification:**
- **With `deviceName`**: Verifies against specific device only
- **Without `deviceName`**: Verifies against all user's TOTP devices

**Response (Success):**
```json
{
  "message": "TOTP code is valid"
}
```

**Response (Multiple Devices, No deviceName):**
```json
{
  "message": "TOTP code is valid (validated with device: iPhone 15 Pro)"
}
```
</details>

<details>
<summary><b>📋 List TOTP Devices</b></summary>

Get all TOTP devices registered for a user.

```http
GET /{{USER_ID}}/list
Authorization: Bearer {{TOKEN}}
```

**Response:**
```json
{
  "devices": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "deviceName": "iPhone 15 Pro",
      "createdDate": 1704067200000
    },
    {
      "id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
      "deviceName": "iPad Air",
      "createdDate": 1704153600000
    }
  ],
  "count": 2
}
```
</details>

<details>
<summary><b>🗑️ Remove TOTP Credentials</b></summary>

#### Remove Specific Device
```http
DELETE /{{USER_ID}}/disable/{{CREDENTIAL_ID}}
Authorization: Bearer {{TOKEN}}
```

**Response:**
```json
{
  "message": "TOTP credential removed successfully"
}
```

#### Remove All Devices
```http
DELETE /{{USER_ID}}/disable
Authorization: Bearer {{TOKEN}}
```

**Response:**
```json
{
  "message": "TOTP disabled successfully",
  "removed_credentials": 2
}
```
</details>

## 🔒 Authentication

All API endpoints require authentication via service accounts:

### Prerequisites
1. **Bearer Token**: Include in `Authorization` header
2. **Service Account**: Caller must be a service account
3. **Proper Permissions**: Service account needs user management permissions

### Example Request
```bash
curl -X GET \
  https://keycloak.example.com/realms/master/totp-api/USER_ID/list \
  -H 'Authorization: Bearer YOUR_ACCESS_TOKEN'
```

## 🧩 Integration Examples

<details>
<summary><b>Java/Kotlin Example</b></summary>

```kotlin
// Generate TOTP secret
val response = httpClient.get("$keycloakUrl/realms/$realm/totp-api/$userId/generate") {
    header("Authorization", "Bearer $token")
}

// Register TOTP
val registerRequest = RegisterTOTPRequest(
    deviceName = "Mobile App",
    encodedSecret = secret,
    initialCode = "123456",
    overwrite = false
)

httpClient.post("$keycloakUrl/realms/$realm/totp-api/$userId/register") {
    header("Authorization", "Bearer $token")
    contentType(ContentType.Application.Json)
    setBody(registerRequest)
}
```
</details>

<details>
<summary><b>Node.js/TypeScript Example</b></summary>

```typescript
import axios, { AxiosInstance } from 'axios';

interface TotpApiClient {
  generate(userId: string): Promise<{ encodedSecret: string; qrCode: string }>;
  register(userId: string, data: RegisterData): Promise<{ message: string }>;
  verify(userId: string, data: VerifyData): Promise<{ message: string }>;
  list(userId: string): Promise<{ devices: Device[]; count: number }>;
  disable(userId: string, credentialId?: string): Promise<{ message: string }>;
}

interface RegisterData {
  deviceName: string;
  encodedSecret: string;
  initialCode: string;
  overwrite?: boolean;
}

interface VerifyData {
  code: string;
  deviceName?: string;
}

interface Device {
  id: string;
  deviceName: string;
  createdDate: number;
}

class KeycloakTotpClient implements TotpApiClient {
  private client: AxiosInstance;
  
  constructor(
    private keycloakUrl: string,
    private realm: string,
    private token: string
  ) {
    this.client = axios.create({
      baseURL: `${keycloakUrl}/realms/${realm}/totp-api`,
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });
  }

  async generate(userId: string) {
    const { data } = await this.client.get(`/${userId}/generate`);
    return data;
  }

  async register(userId: string, registerData: RegisterData) {
    const { data } = await this.client.post(`/${userId}/register`, registerData);
    return data;
  }

  async verify(userId: string, verifyData: VerifyData) {
    const { data } = await this.client.post(`/${userId}/verify`, verifyData);
    return data;
  }

  async list(userId: string) {
    const { data } = await this.client.get(`/${userId}/list`);
    return data;
  }

  async disable(userId: string, credentialId?: string) {
    const endpoint = credentialId 
      ? `/${userId}/disable/${credentialId}`
      : `/${userId}/disable`;
    const { data } = await this.client.delete(endpoint);
    return data;
  }
}

// Usage example
async function setupTotp() {
  const client = new KeycloakTotpClient(
    'https://keycloak.example.com',
    'master',
    'your-access-token'
  );

  try {
    // Generate TOTP secret
    const { encodedSecret, qrCode } = await client.generate('user-123');
    console.log('Secret:', encodedSecret);
    
    // Display QR code to user (in a real app, convert base64 to image)
    // ...
    
    // Register after user scans QR code
    await client.register('user-123', {
      deviceName: 'iPhone 15 Pro',
      encodedSecret,
      initialCode: '123456', // Code from authenticator app
      overwrite: false
    });
    
    // Later: Verify TOTP code
    const verifyResult = await client.verify('user-123', {
      code: '654321'
      // deviceName is optional - if not provided, verifies against all devices
    });
    console.log(verifyResult.message);
    
    // List all devices
    const { devices } = await client.list('user-123');
    console.log(`User has ${devices.length} TOTP devices`);
    
  } catch (error) {
    if (axios.isAxiosError(error)) {
      console.error('API Error:', error.response?.data);
    } else {
      console.error('Error:', error);
    }
  }
}
```
</details>

<details>
<summary><b>Python Example</b></summary>

```python
import requests

# Generate TOTP secret
headers = {"Authorization": f"Bearer {token}"}
response = requests.get(
    f"{keycloak_url}/realms/{realm}/totp-api/{user_id}/generate",
    headers=headers
)

secret_data = response.json()
print(f"Secret: {secret_data['encodedSecret']}")

# Verify TOTP code
verify_data = {"code": "123456"}  # deviceName is optional
response = requests.post(
    f"{keycloak_url}/realms/{realm}/totp-api/{user_id}/verify",
    headers=headers,
    json=verify_data
)
```
</details>

## 📝 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🐛 Issues

Found a bug or have a feature request? Please open an issue on the [GitHub repository](https://github.com/rafaelb13/keycloak-totp-spi/issues).

---
