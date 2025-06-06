[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Username,
    
    [Parameter(Mandatory=$true)]
    [string]$Password,
    
    [Parameter(Mandatory=$false)]
    [string]$Hostname,
    
    [Parameter(Mandatory=$false)]
    [string]$HostIP,
    
    [Parameter(Mandatory=$false)]
    [string]$SystemName,
    
    [Parameter(Mandatory=$false)]
    [string]$SystemIP
)

# Configure logging - create directory if it doesn't exist
$LogDir = Join-Path $PSScriptRoot "logs"
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$LogPath = Join-Path $LogDir "pra_vault.log"

function Write-Log {
    param($Message)
    try {
        $LogMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'):INFO:$Message"
        Add-Content -Path $LogPath -Value $LogMessage -ErrorAction Stop
        Write-Verbose $LogMessage
    }
    catch {
        Write-Warning "Failed to write to log file: $_"
        Write-Verbose $LogMessage
    }
}

function Write-ErrorLog {
    param($Message)
    try {
        $LogMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'):ERROR:$Message"
        Add-Content -Path $LogPath -Value $LogMessage -ErrorAction Stop
        Write-Error $LogMessage
    }
    catch {
        Write-Warning "Failed to write to error log file: $_"
        Write-Error $LogMessage
    }
}

# Ignore SSL certificate warnings
Add-Type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# Define BeyondTrust PRA configuration
$PraUrl = "https://wharrispra.beyondtrustcloud.com"
$ClientId = "placeholder"
$ClientSecret = "placeholder"

# Create API key from client credentials
$ApiKey = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${ClientId}:${ClientSecret}"))

# Create and maintain web session
$WebSession = $null

function Get-BearerToken {
    try {
        Write-Log "Attempting to get bearer token..."
        
        # Log the URL (safe to log)
        Write-Log "Token endpoint URL: $PraUrl/oauth2/token"
        
        # Create and log headers (mask sensitive data)
        $Headers = @{
            'Authorization' = "Basic $ApiKey"
            'Content-Type' = 'application/x-www-form-urlencoded'
        }
        
        # Log headers safely (masking Authorization)
        $HeadersLog = $Headers.Clone()
        $HeadersLog['Authorization'] = "Basic [MASKED]"
        Write-Log "Request Headers: $($HeadersLog | ConvertTo-Json)"
        
        # Log request parameters
        Write-Log "Request Method: POST"
        Write-Log "Request Body: grant_type=client_credentials"
        
        $Params = @{
            Method = 'POST'
            Uri = "$PraUrl/oauth2/token"
            Headers = $Headers
            Body = 'grant_type=client_credentials'
            SessionVariable = 'WebSession'
        }
        
        # Add verbose error handling
        try {
            $Response = Invoke-RestMethod @Params -ErrorVariable RestError
            $Script:WebSession = $WebSession
            Write-Log "Bearer token obtained successfully"
            return $Response.access_token
        }
        catch [System.Net.WebException] {
            $StatusCode = [int]$_.Exception.Response.StatusCode
            $StatusDescription = $_.Exception.Response.StatusDescription
            $RawResponse = if ($_.Exception.Response) {
                $Reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $Reader.ReadToEnd()
            } else { "No response body" }
            
            Write-ErrorLog "HTTP Status Code: $StatusCode"
            Write-ErrorLog "Status Description: $StatusDescription"
            Write-ErrorLog "Raw Response: $RawResponse"
            
            # Additional debugging for 401 errors
            if ($StatusCode -eq 401) {
                Write-ErrorLog "Authorization failed. Please verify:"
                Write-ErrorLog "1. The ClientId and ClientSecret are correct"
                Write-ErrorLog "2. The API key is being properly generated"
                Write-ErrorLog "3. The credentials have proper permissions"
                
                # Log the length of the API key to help debug without exposing it
                Write-Log "API Key length: $($ApiKey.Length) characters"
                
                # Log the format of the Authorization header (masked)
                Write-Log "Authorization header format check: $(if($Headers['Authorization'].StartsWith('Basic ')){'Valid'}else{'Invalid'}) Basic prefix"
            }
            
            throw
        }
    }
    catch {
        Write-ErrorLog "Failed to get bearer token: $_"
        throw
    }
}

function Test-AccountExists {
    param($Token, $Username)
    try {
        $Headers = @{
            'Accept' = 'application/json'
            'Authorization' = "Bearer $Token"
        }
        
        $Params = @{
            Method = 'GET'
            Uri = "$PraUrl/api/config/v1/vault/account?name=$Username"
            Headers = $Headers
            WebSession = $WebSession
        }
        
        $Response = Invoke-RestMethod @Params
        $Account = $Response | Where-Object { $_.name -eq $Username }
        return $Account.id
    }
    catch {
        Write-ErrorLog "Failed to check if account exists: $_"
        throw
    }
}

function Set-VaultCredentials {
    param($Token, $Username, $Password, $AccountId)
    try {
        $Headers = @{
            'Authorization' = "Bearer $Token"
            'Content-Type' = 'application/json'
            'Accept' = 'application/json'
        }
        
        $Body = @{
            type = "username_password"
            name = $Username
            username = $Username
            password = $Password
        } | ConvertTo-Json
        
        if ($AccountId) {
            # Update existing account
            $Params = @{
                Method = 'PATCH'
                Uri = "$PraUrl/api/config/v1/vault/account/$AccountId"
                Headers = $Headers
                Body = $Body
                WebSession = $WebSession
            }
            $Operation = "update"
        }
        else {
            # Create new account
            $Params = @{
                Method = 'POST'
                Uri = "$PraUrl/api/config/v1/vault/account"
                Headers = $Headers
                Body = $Body
                WebSession = $WebSession
            }
            $Operation = "create"
        }
        
        $Response = Invoke-RestMethod @Params
        Write-Log "Account ${Operation}d successfully"
    }
    catch {
        Write-ErrorLog "Failed to $Operation account: $_"
        throw
    }
}

# Main execution block
try {
    Write-Log "Script started"
    $Token = Get-BearerToken
    $AccountId = Test-AccountExists -Token $Token -Username $Username
    Set-VaultCredentials -Token $Token -Username $Username -Password $Password -AccountId $AccountId
    Write-Log "Script completed successfully"
}
catch {
    Write-ErrorLog "Script failed: $_"
    exit 1
}