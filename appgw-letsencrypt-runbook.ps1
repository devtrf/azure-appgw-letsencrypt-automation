<#
.SYNOPSIS
    Automated certificate renewal for Azure Application Gateway using Let's Encrypt and ACME-PS.
    Updated for 2025 standards (Managed Identity, ACME-PS v1.5.9+).

.DESCRIPTION
    This script performs the following actions:
    1. Authenticates to Azure using Managed Identity.
    2. Registers or loads an ACME account with Let's Encrypt.
    3. Handles HTTP-01 challenge by uploading tokens to an Azure Storage Account.
    4. Issues/Renews the certificate.
    5. Updates the SSL certificate on the specified Azure Application Gateway.

.PARAMETER Domain
    The DNS domain name to issue the certificate for.
.PARAMETER EmailAddress
    The contact email address for Let's Encrypt.
.PARAMETER STResourceGroupName
    Resource Group name of the Storage Account.
.PARAMETER StorageName
    Name of the Storage Account used for challenges.
.PARAMETER AGResourceGroupName
    Resource Group name of the Application Gateway.
.PARAMETER AGName
    Name of the Application Gateway.
.PARAMETER AGCertName
    Name of the SSL certificate on the Application Gateway to be updated.
.PARAMETER ContainerName
    Name of the blob container used for ACME challenges. Default is 'appgwletsencrypt'.
.PARAMETER ACMEEnvironment
    The ACME environment to use: 'LetsEncrypt' (Production) or 'LetsEncrypt-Staging' (Testing). Default is 'LetsEncrypt-Staging'.

.EXAMPLE
    ./appgw-letsencrypt-runbook.ps1 -Domain "api.example.com" -EmailAddress "admin@example.com" -STResourceGroupName "rg-storage" -StorageName "stchallenges" -AGResourceGroupName "rg-network" -AGName "appgw-prod" -AGCertName "api-cert"
#>

Param(
    [Parameter(Mandatory = $true)]
    [string]$Domain,

    [Parameter(Mandatory = $true)]
    [string]$EmailAddress,

    [Parameter(Mandatory = $true)]
    [string]$STResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$StorageName,

    [Parameter(Mandatory = $true)]
    [string]$AGResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$AGName,

    [Parameter(Mandatory = $true)]
    [string]$AGCertName,

    [Parameter(Mandatory = $true)]
    [string]$ContainerName,

    [ValidateSet("LetsEncrypt", "LetsEncrypt-Staging")]
    [string]$ACMEEnvironment = "LetsEncrypt"
)

# 1. Explicitly import modules to avoid conflicts in Azure Automation
Write-Output "Importing required modules..."
Import-Module Az.Accounts
Import-Module Az.Storage
Import-Module Az.Network
Import-Module Az.Resources
Import-Module ACME-PS

# 2. Authenticate using Managed Identity
Write-Output "Connecting to Azure using Managed Identity..."
try {
    Connect-AzAccount -Identity -ErrorAction Stop
}
catch {
    Write-Error "Failed to connect to Azure via Managed Identity. Ensure it is enabled on the Automation Account."
    throw $_
}

# 3. Setup ACME State
$acmeStatePath = Join-Path $env:TEMP "ACMEState"
if (-not (Test-Path $acmeStatePath)) {
    New-Item -ItemType Directory -Path $acmeStatePath | Out-Null
}

Write-Output "Initializing ACME state for environment: $ACMEEnvironment"
New-ACMEState -Path $acmeStatePath -ErrorAction SilentlyContinue 
Get-ACMEServiceDirectory -State $acmeStatePath -ServiceName $ACMEEnvironment

# 4. Handle ACME Account
Write-Output "Registering/Updating ACME account for $EmailAddress..."
New-ACMENonce -State $acmeStatePath
New-ACMEAccountKey -State $acmeStatePath -ErrorAction SilentlyContinue
New-ACMEAccount -State $acmeStatePath -EmailAddresses @($EmailAddress) -AcceptTOS -ErrorAction SilentlyContinue

# 5. Create Order
Write-Output "Creating new order for domain: $Domain"
$identifier = New-ACMEIdentifier $Domain
$order = New-ACMEOrder -State $acmeStatePath -Identifiers $identifier

# 6. Fulfillment of Challenges
Write-Output "Processing authorizations for order..."
$authZs = Get-ACMEAuthorization -State $acmeStatePath -Order $order

foreach ($authZ in $authZs) {
    if ($authZ.Status -eq "valid") {
        Write-Output "Authorization for $($authZ.Identifier.Value) is already valid."
        continue
    }

    Write-Output "Handling http-01 challenge for $($authZ.Identifier.Value)..."
    $challenge = Get-ACMEChallenge -State $acmeStatePath -Authorization $authZ -Type "http-01"
    
    # Upload challenge file to Storage Account
    $blobName = ".well-known/acme-challenge/$($challenge.Token)"
    $tempFile = Join-Path $env:TEMP $challenge.Token
    Set-Content -Path $tempFile -Value $challenge.Data.Content -NoNewline
    
    Write-Output "Uploading challenge token to storage: $StorageName / public / $blobName"
    try {
        $script:storageAccount = Get-AzStorageAccount -ResourceGroupName $STResourceGroupName -Name $StorageName -ErrorAction Stop
        $script:ctx = $script:storageAccount.Context
        Set-AzStorageBlobContent -File $tempFile -Container $ContainerName -Context $script:ctx -Blob $blobName -Force -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to upload challenge to storage account."
        throw $_
    }
    finally {
        if (Test-Path $tempFile) { Remove-Item $tempFile }
    }

    # Signal ACME server
    Write-Output "Signaling ACME server that challenge is ready..."
    $challenge | Complete-ACMEChallenge -State $acmeStatePath
}

# 7. Wait for Order to be Ready
Write-Output "Waiting for order status to reach 'ready'..."
while ($order.Status -notin ("ready", "invalid")) {
    Start-Sleep -Seconds 5
    $order = $order | Update-ACMEOrder -State $acmeStatePath -PassThru
}

if ($order.Status -eq "invalid") {
    Write-Error "Order reached an invalid state. Check ACME server logs."
    throw "ACME Order Invalid"
}

# 8. Finalize Order and Issue Certificate
Write-Output "Finalizing order and generating certificate key..."
$pfxPassword = ConvertTo-SecureString -String ([Guid]::NewGuid().ToString("N")) -AsPlainText -Force
$pfxPath = Join-Path $env:TEMP "$Domain.pfx"

# Generate a certificate key
$certKey = New-ACMECertificateKey -Path (Join-Path $acmeStatePath "$Domain.key.xml")

# Complete the order with the certificate key
Complete-ACMEOrder -State $acmeStatePath -Order $order -CertificateKey $certKey

Write-Output "Waiting for certificate issuance..."
while (-not $order.CertificateUrl) {
    Start-Sleep -Seconds 10
    $order = $order | Update-ACMEOrder -State $acmeStatePath -PassThru
}

Write-Output "Exporting certificate to $pfxPath"
Export-ACMECertificate -State $acmeStatePath -Order $order -CertificateKey $certKey -Path $pfxPath -Password $pfxPassword

# 9. Update Application Gateway
Write-Output "Updating Application Gateway: $AGName with new certificate..."
try {
    $appgw = Get-AzApplicationGateway -ResourceGroupName $AGResourceGroupName -Name $AGName -ErrorAction Stop
    
    # Check if certificate exists, otherwise it will add it (though usually we update an existing one)
    $existingCert = $appgw.SslCertificates | Where-Object { $_.Name -eq $AGCertName }
    
    if ($existingCert) {
        Write-Output "Updating existing SSL certificate: $AGCertName"
        Set-AzApplicationGatewaySslCertificate -Name $AGCertName -ApplicationGateway $appgw -CertificateFile $pfxPath -Password $pfxPassword -ErrorAction Stop
    }
    else {
        Write-Output "Adding new SSL certificate: $AGCertName"
        Add-AzApplicationGatewaySslCertificate -Name $AGCertName -ApplicationGateway $appgw -CertificateFile $pfxPath -Password $pfxPassword -ErrorAction Stop
    }
    
    Set-AzApplicationGateway -ApplicationGateway $appgw -ErrorAction Stop
    Write-Output "Application Gateway updated successfully."
}
catch {
    Write-Error "Failed to update Application Gateway."
    throw $_
}
finally {
    if (Test-Path $pfxPath) { Remove-Item $pfxPath }
}

# 10. Cleanup Storage
Write-Output "Cleaning up challenge blobs..."
try {
    foreach ($authZ in $authZs) {
        $challenge = Get-ACMEChallenge -State $acmeStatePath -Authorization $authZ -Type "http-01"
        $blobName = ".well-known/acme-challenge/$($challenge.Token)"
        Remove-AzStorageBlob -Container $ContainerName -Context $script:ctx -Blob $blobName -ErrorAction SilentlyContinue
    }
}
catch {
    Write-Warning "Failed to cleanup some challenge blobs."
}

Write-Output "SSL Certificate Renewal and Update process completed."
