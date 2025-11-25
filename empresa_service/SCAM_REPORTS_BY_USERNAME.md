# Scam Reports by Username Implementation

## Overview
The system now supports retrieving scam reports based on the logged-in user's username. The username is automatically extracted from the JWT token in the Authorization header.

## How It Works

1. **Authentication**: User logs in and receives a JWT token containing their username
2. **Request**: User makes a GET request to `/api/scam-reports/me` with the JWT token in the Authorization header
3. **Username Extraction**: Spring Security automatically extracts the username from the token
4. **Company Lookup**: The system finds the company record using the username
5. **Scam Reports Retrieval**: Using the company ID, the system fetches all associated scam reports from the golpes_service

## Endpoints

### GET /api/scam-reports/me
Retrieves all scam reports for the authenticated user's company.

**Headers:**
```
Authorization: Bearer <JWT_TOKEN>
```

**Response:**
```json
[
  {
    "id": 1,
    "nome": "João Silva",
    "cidade": "São Paulo",
    "meioDeContato": "WhatsApp",
    "descricao": "Tentativa de golpe via WhatsApp",
    "emailOuTelefone": "11999999999",
    "empresa": "EMPRESA_TESTE",
    "createdAt": "2025-11-24T10:30:00"
  }
]
```

**Note:** CPF data is excluded from the response for privacy protection.

### GET /api/scam-reports/my-company
Alternative endpoint with the same functionality.

## Implementation Details

### ScamRetrievalService
Added method `getScamReportsByUsername(String username)`:
- Takes the username as parameter
- Looks up the company in the database using `EmpresaRepository.findByUsuario()`
- Retrieves scam reports using the company ID
- Returns empty list if company not found

### ScamReportController
New controller with two endpoints:
- `/api/scam-reports/me` - Uses Authentication parameter injection
- `/api/scam-reports/my-company` - Uses SecurityContextHolder directly

Both endpoints automatically extract the username from the authenticated user.

## Security
- Endpoints are protected by Spring Security
- Only authenticated users can access their own company's scam reports
- Users cannot access other companies' data
- CPF information is filtered out for privacy

## Testing
See `test-requests.http` for example requests.

1. First, login to get a JWT token:
```http
POST http://localhost:8082/api/auth/login
Content-Type: application/json

{
  "usuario": "EMPRESA_TESTE",
  "password": "senha123"
}
```

2. Use the token to retrieve scam reports:
```http
GET http://localhost:8082/api/scam-reports/me
Authorization: Bearer <token_from_login>
```
