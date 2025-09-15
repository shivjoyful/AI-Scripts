# --- Automatic Wireshark PCAP Analyzer for LAN (using TShark) ---
# Designed to help identify common network bottlenecks and issues quickly.
# Author: Gemini-2.5-flash
# Date: 2025-09-15
# Version 1

# IMPORTANT PREREQUISITE:
# This script relies on 'tshark', the command-line network protocol analyzer
# that comes with Wireshark. You MUST have Wireshark installed on the machine
# where you run this script (or have tshark.exe in your system's PATH).
# If Wireshark is installed, tshark.exe is usually located in its installation directory,
# e.g., 'C:\Program Files\Wireshark\tshark.exe'.
# You can download Wireshark from: https://www.wireshark.org/download.html
# After installation, ensure 'C:\Program Files\Wireshark\' is added to your System PATH
# environment variable, or modify the $tsharkPath variable below.

function Invoke-TsharkAnalysis {
    param(
        [Parameter(Mandatory=$true)]
        [string]$PcapFilePath,

        [Parameter(Mandatory=$true)]
        [string]$AnalysisType,

        [string]$CustomFilter = "",

        [string]$DomainControllerIP = "" # Optional: Specify if analysis needs to target a DC
    )

    Write-Host "[DEBUG] Inside Invoke-TsharkAnalysis function." -ForegroundColor Gray

    # --- Define error code explanations ---
    # Kerberos Error Codes (from RFC 4120 and common interpretations)
    $kerberosErrorMap = @{
        "6"  = "KDC_ERR_C_OLD_MAST_KVNO (Client key is too old/KDC has older key). Common for clock skew or password replication issues."
        "7"  = "KDC_ERR_BADOPTION (Incorrect Kerberos options). Client sent invalid/unsupported options."
        "24" = "KDC_ERR_PADATA_TYPE_NOSUPP (KDC has no support for pre-authentication data type). Client using unsupported pre-auth."
        "25" = "KDC_ERR_PREAUTH_REQUIRED (Additional pre-authentication is required). Often normal negotiation, but check for no follow-up."
        # Add more Kerberos errors here if you encounter them frequently and want to explain them.
    }

    # SMB NT Status Codes
    $smbStatusMap = @{
        "0xC000006D" = "STATUS_LOGON_FAILURE (Incorrect username/password or account restrictions)."
        # Add more SMB status codes here if relevant for other analysis types.
    }

    # --- Locate tshark.exe ---
    $tsharkPath = (Get-Command tshark.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)
    if (-not $tsharkPath) {
        $potentialTsharkPath = "C:\Program Files\Wireshark\tshark.exe"
        if (Test-Path $potentialTsharkPath) {
            $tsharkPath = $potentialTsharkPath
            Write-Host "[DEBUG] Found tshark.exe at fallback path: $tsharkPath" -ForegroundColor Gray
        } else {
            Write-Error "tshark.exe not found. Please install Wireshark or ensure 'C:\Program Files\Wireshark\' is in your system's PATH."
            Write-Host "Download Wireshark from: https://www.wireshark.org/download.html" -ForegroundColor Yellow
            Write-Host "[DEBUG] Exiting due to tshark.exe not found." -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "[DEBUG] Found tshark.exe in PATH: $tsharkPath" -ForegroundColor Gray
    }

    if (-not (Test-Path $PcapFilePath)) {
        Write-Error "PCAP file not found: $PcapFilePath"
        Write-Host "[DEBUG] Exiting due to PCAP file not found." -ForegroundColor Red
        exit 1
    }

    Write-Host "`n--- Running TShark Analysis ---" -ForegroundColor Cyan
    Write-Host "PCAP File: $PcapFilePath" -ForegroundColor Cyan
    Write-Host "Analysis Type: $AnalysisType" -ForegroundColor Cyan
    if ($DomainControllerIP) {
        Write-Host "Targeting DC IP: $DomainControllerIP" -ForegroundColor Cyan
    }

    $tsharkArgs = @("-r", "`"$PcapFilePath`"", "-T", "fields")
    $displayFilter = ""
    # Base output fields, more added per analysis type
    $outputFields = @("frame.number", "frame.time_relative", "ip.src", "ip.dst") 

    Write-Host "[DEBUG] AnalysisType: $AnalysisType" -ForegroundColor Gray
    switch ($AnalysisType) {
        "AuthenticationFailures" {
            $displayFilter = "kerberos.error_code ne 0 || smb.nt_status == 0xC000006D"
            $outputFields += @("kerberos.error_code", "smb.nt_status")
            Write-Host "Searching for: Kerberos errors or SMB/NTLM logon failures (0xC000006D)" -ForegroundColor Yellow
        }
        "GPO_Traffic" {
            $displayFilter = "(ldap.port == 389 || ldap.port == 636 || kerberos.msg_type) || (smb2.filename contains 'sysvol' || smb.tree eq '\\*\SYSVOL' || smb3.filename contains 'sysvol')"
            if ($DomainControllerIP) {
                $displayFilter = "($displayFilter) && (ip.addr == '$DomainControllerIP')"
            }
            $outputFields += @("ldap.dn", "kerberos.error_code", "smb.tree", "smb2.filename") 
            Write-Host "Searching for: LDAP, Kerberos, SMB/SMB2/SMB3 traffic (SYSVOL) related to GPO." -ForegroundColor Yellow
        }
        "DNS_Issues" {
            $displayFilter = "dns.flags.response == 1 && dns.flags.rcode != 0 || dns.time > 0.1"
            $outputFields += @("dns.qry.name", "dns.flags.rcode", "dns.time")
            Write-Host "Searching for: DNS errors or responses slower than 100ms." -ForegroundColor Yellow
        }
        "Slow_HTTP_Responses" {
            $displayFilter = "http.response.code >= 400 || http.time > 1.0"
            $outputFields += @("http.request.full_uri", "http.response.code", "http.time")
            Write-Host "Searching for: HTTP client errors (4xx), server errors (5xx), or responses slower than 1 second." -ForegroundColor Yellow
        }
        "Custom_Filter" {
            if ([string]::IsNullOrWhiteSpace($CustomFilter)) {
                Write-Error "Custom_Filter selected, but no CustomFilter string provided."
                Write-Host "[DEBUG] Exiting due to empty CustomFilter." -ForegroundColor Red
                exit 1
            }
            $displayFilter = $CustomFilter
            # For custom filter, we cannot pre-define outputFields accurately from here,
            # but we still include the base fields. If the user wants specific fields,
            # they would need to extend this script to allow specifying them.
            Write-Host "Using Custom Filter: '$CustomFilter'" -ForegroundColor Yellow
        }
        default {
            Write-Error "Invalid AnalysisType: $AnalysisType"
            Write-Host "[DEBUG] Exiting due to invalid AnalysisType." -ForegroundColor Red
            exit 1
        }
    }

    $tsharkArgs += @("-Y", "`"$displayFilter`"")
    foreach ($field in $outputFields) {
        $tsharkArgs += @("-e", $field)
    }
    # Ensure header and CSV separator for parsing
    $tsharkArgs += @("-E", "header=y", "-E", "separator=,")

    Write-Host "[DEBUG] Full tshark arguments constructed." -ForegroundColor Gray
    Write-Host "`nExecuting TShark Command (may take time for large files):" -ForegroundColor DarkCyan
    Write-Host "$tsharkPath $($tsharkArgs -join ' ')" -ForegroundColor DarkCyan
    Write-Host "`n--- TShark Output (CSV format with Explanations) ---" -ForegroundColor DarkGreen

    try {
        # Redirect stderr to stdout to capture any tshark warnings/errors in the output stream
        $tsharkOutputRaw = & "$tsharkPath" $tsharkArgs 2>&1 
        $outputLines = $tsharkOutputRaw -split "`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

        # Construct the expected header including the Explanation column, for consistent display
        $displayHeader = ($outputFields -join ',') + ",Explanation"

        if ($outputLines.Count -eq 0) {
            Write-Host $displayHeader # Print the correct header even if no output
            Write-Host "No output received from TShark. This could mean no matching packets, or an error occurred silently." -ForegroundColor Yellow
        } elseif ($outputLines.Count -eq 1) {
            # Only header present from TShark (meaning no data rows matched the filter).
            # We print our consistently constructed header.
            Write-Host $displayHeader 
            Write-Host "No matching packets found for this analysis type and filter." -ForegroundColor Yellow
        } else {
            # Header and data present from TShark.
            # We must use TShark's actual header for ConvertFrom-Csv for accurate parsing,
            # but we still print our consistently formatted $displayHeader for the user.
            $headerFromTshark = $outputLines[0]
            $dataLines = $outputLines | Select-Object -Skip 1

            # Convert to CSV objects for easier processing
            $csvData = $dataLines | ConvertFrom-Csv -Header ($headerFromTshark -split ',')

            Write-Host $displayHeader # Print the consistently formatted header for the user

            # Process and print each data row with explanations
            foreach ($row in $csvData) {
                $explanation = ""
                $kerr = $null
                $smerr = $null
                
                # Safely access properties, as they might not exist depending on the TShark output fields
                if ($row.PSObject.Properties.Name -contains "kerberos.error_code") { $kerr = $row."kerberos.error_code" }
                if ($row.PSObject.Properties.Name -contains "smb.nt_status") { $smerr = $row."smb.nt_status" }
                
                if (-not [string]::IsNullOrWhiteSpace($kerr)) {
                    $explanation += $kerberosErrorMap[$kerr]
                }
                if (-not [string]::IsNullOrWhiteSpace($smerr)) {
                    # If both Kerberos and SMB errors exist, add a separator
                    if (-not [string]::IsNullOrWhiteSpace($explanation)) { $explanation += "; " }
                    $explanation += $smbStatusMap[$smerr]
                }

                # Fallback if a specific explanation isn't in our maps
                if ([string]::IsNullOrWhiteSpace($explanation)) {
                    if (-not [string]::IsNullOrWhiteSpace($kerr) -or -not [string]::IsNullOrWhiteSpace($smerr)) {
                        $explanation = "No specific explanation available for this code in script."
                    }
                }

                # Construct the output line dynamically based on the properties found in the CSV object
                $outputLine = ""
                $firstField = $true
                # Iterate through the fields that TShark actually outputted
                foreach ($propName in ($headerFromTshark -split ',')) {
                    if (-not $firstField) { $outputLine += "," }
                    $outputLine += "$($row.$propName)"
                    $firstField = $false
                }
                $outputLine += ",$explanation" # Append the explanation
                Write-Host $outputLine
            }
        }
    }
    catch {
        Write-Error "Error running tshark or processing its output: $($_.Exception.Message)"
        Write-Host "Check if tshark.exe is accessible, the PCAP file is valid/not corrupt, and the tshark display filter is correct." -ForegroundColor Red
        Write-Host "Also ensure your PowerShell version is reasonably modern (v3+)." -ForegroundColor Yellow
        Write-Host "[DEBUG] Exiting due to tshark execution error." -ForegroundColor Red
        exit 1
    }

    Write-Host "`n--- Analysis Complete ---`n" -ForegroundColor Cyan
}

# --- Main Script Interaction ---
Write-Host "`n*** Wireshark PCAP Analysis Script ***" -ForegroundColor Green
Write-Host "This script uses TShark (part of Wireshark) to analyze .pcap files." -ForegroundColor DarkYellow
Write-Host "Ensure Wireshark is installed and tshark.exe is in your system's PATH!" -ForegroundColor DarkYellow
Write-Host "[DEBUG] Starting main script interaction." -ForegroundColor Gray

$pcapFile = Read-Host "Enter the full path to your .pcap or .pcapng file (e.g., C:\captures\my_capture.pcapng)"
if ([string]::IsNullOrWhiteSpace($pcapFile)) {
    Write-Error "PCAP file path cannot be empty. Exiting."
    Write-Host "[DEBUG] Exiting due to empty PCAP file path input." -ForegroundColor Red
    exit 1
}

$menuOptions = @(
    "1. Authentication Failures (Kerberos/NTLM related)",
    "2. GPO Traffic (LDAP/SMB/Kerberos related)",
    "3. DNS Issues (Errors or Slow Responses)",
    "4. Slow HTTP Responses (Client/Server Errors or Delays)",
    "5. Custom Filter (for advanced users who know TShark display filters)"
)
Write-Host "`nSelect the type of analysis you want to perform:" -ForegroundColor Green
$menuOptions | ForEach-Object { Write-Host $_ }

$choice = Read-Host "Enter your choice (1-5)"
$analysisType = switch ($choice) {
    "1" { "AuthenticationFailures" }
    "2" { "GPO_Traffic" }
    "3" { "DNS_Issues" }
    "4" { "Slow_HTTP_Responses" }
    "5" { "Custom_Filter" }
    default {
        Write-Error "Invalid choice. Exiting."
        Write-Host "[DEBUG] Exiting due to invalid menu choice." -ForegroundColor Red
        exit 1
    }
}

$customFilterInput = ""
if ($analysisType -eq "Custom_Filter") {
    $customFilterInput = Read-Host "Enter your TShark display filter (e.g., http.request.method == GET && http.response.code == 404)"
    if ([string]::IsNullOrWhiteSpace($customFilterInput)) {
        Write-Error "Custom filter cannot be empty for Custom_Filter analysis type. Exiting."
        Write-Host "[DEBUG] Exiting due to empty custom filter input." -ForegroundColor Red
        exit 1
    }
}

$dcIPInput = ""
if ($analysisType -eq "GPO_Traffic") {
    $dcIPInput = Read-Host "Optional: Enter Domain Controller IP to narrow GPO traffic analysis (press Enter to skip)"
    # Basic IP validation
    if ($dcIPInput -notmatch "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$" -and -not [string]::IsNullOrWhiteSpace($dcIPInput)) {
        Write-Warning "The provided DC IP '$dcIPInput' does not appear to be a valid IP address. It will still be used, but verify correctness."
    }
}

Write-Host "[DEBUG] Calling Invoke-TsharkAnalysis function." -ForegroundColor Gray
# Call the analysis function
Invoke-TsharkAnalysis -PcapFilePath $pcapFile -AnalysisType $analysisType -CustomFilter $customFilterInput -DomainControllerIP $dcIPInput
Write-Host "[DEBUG] Script finished." -ForegroundColor Gray
