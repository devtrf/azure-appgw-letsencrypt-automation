# Azure Application Gateway Let's Encrypt Automation

Automate SSL certificate renewals for Azure Application Gateway using Let's Encrypt and Azure Automation. Updated for 2025 standards using Managed Identity and `ACME-PS` v1.5.9+.

## Overview

This project provides a PowerShell runbook (`appgw-letsencrypt-runbook.ps1`) **primarily designed to run as an Azure Automation Runbook**. It automates the entire lifecycle of a Let's Encrypt certificate:
1. **Authentication**: Uses Azure Managed Identity for secure access.
2. **ACME Account**: Registers or loads an ACME account.
3. **Challenge Fulfillment**: Handles HTTP-01 challenges by uploading tokens to an Azure Storage Account.
4. **Issuance**: Renews/Issues the certificate via ACME-PS.
5. **Deployment**: Updates the SSL certificate on the specified Azure Application Gateway.

## Prerequisites

- **Azure Automation Account**: Enabled with **Managed Identity**.
- **Azure Storage Account**: Used to host ACME challenge tokens.
- **Azure Application Gateway**: With an existing HTTPS listener (or ready to be updated).
- **Required Modules**: Ensure the following are imported into your Automation Account:
  - `Az.Accounts`
  - `Az.Storage`
  - `Az.Network`
  - `Az.Resources`
  - `ACME-PS` (v1.5.9+)

## Setup Instructions

### 1. Storage Account Configuration
- Create a Blob container (e.g., `appgwletsencrypt`).
- The container must be accessible for the Application Gateway to fetch challenge files.
- The script automatically handles the creation of `.well-known/acme-challenge/` path within this container.

### 2. Application Gateway Routing
To satisfy the Let's Encrypt HTTP-01 challenge, you must configure a **Path-based routing rule** on your Application Gateway:
- **Path**: `/.well-known/acme-challenge/*`
- **Action**: Redirect (Permanent) or Proxy to the Storage Account container.
- **Tip**: Ensure the redirection targets the URL of the Storage Account container where the tokens are uploaded.

### 3. Managed Identity Permissions
The Automation Account's Managed Identity needs the following RBAC roles:
- **Storage Blob Data Contributor**: Over the Storage Account container.
- **Network Contributor**: (Or a custom role) over the Application Gateway to update SSL certificates.

## Usage

### Parameters
| Parameter | Description |
| :--- | :--- |
| `Domain` | The DNS domain name (e.g., `api.example.com`). |
| `EmailAddress` | Contact email for Let's Encrypt. |
| `STResourceGroupName`| Resource Group of the Storage Account. |
| `StorageName` | Name of the Storage Account for challenges. |
| `AGResourceGroupName`| Resource Group of the Application Gateway. |
| `AGName` | Name of the Application Gateway. |
| `AGCertName` | Name of the SSL certificate on the App Gateway to update. |
| `ContainerName` | Blob container name (default: `appgwletsencrypt`). |
| `ACMEEnvironment` | `LetsEncrypt` (Production) or `LetsEncrypt-Staging`. |

### Running the Runbook
Invoke the script with the required parameters. It is recommended to test first with `-ACMEEnvironment LetsEncrypt-Staging`.

```powershell
./appgw-letsencrypt-runbook.ps1 `
    -Domain "api.example.com" `
    -EmailAddress "admin@example.com" `
    -STResourceGroupName "rg-storage" `
    -StorageName "stchallenges" `
    -AGResourceGroupName "rg-network" `
    -AGName "appgw-prod" `
    -AGCertName "api-cert" `
    -ContainerName "appgwletsencrypt" `
    -ACMEEnvironment "LetsEncrypt"
```

## Credits
This implementation is based on and inspired by the renewal process concepts described by **David Rodríguez (Intelequia)** in the blog post:
[Automating Azure Application Gateway SSL certificate renewals with Let’s Encrypt and Azure Automation](https://intelequia.com/es/blog/post/automating-azure-application-gateway-ssl-certificate-renewals-with-let-s-encrypt-and-azure-automation).
