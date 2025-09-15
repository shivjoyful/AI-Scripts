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
    # A more extensive, but not exhaustive, list for common troubleshooting.
    # For a complete list, refer to RFC 4120 (Section 7.5.9) and Microsoft documentation.
    $kerberosErrorMap = @{
        "0"  = "KDC_ERR_NONE (No error). This should ideally be a successful response, not an error."
        "1"  = "KDC_ERR_NAME_EXP (Client's entry in KDC database has expired)."
        "2"  = "KDC_ERR_SERVICE_EXP (Server's entry in KDC database has expired)."
        "3"  = "KDC_ERR_C_PW_EXP (Client's password has expired)."
        "4"  = "KDC_ERR_S_PW_EXP (Server's password has expired)."
        "5"  = "KDC_ERR_ETYPE_NOSUPP (Requested encryption type is not supported by KDC or client)."
        "6"  = "KDC_ERR_C_OLD_MAST_KVNO (Client's key is too old/KDC has older key version). Common for clock skew or password replication issues."
        "7"  = "KDC_ERR_S_OLD_MAST_KVNO (Server's key is too old/KDC has older key version). Less common, indicates server key issue."
        "8"  = "KDC_ERR_C_NOTIN_DB (Client not found in Kerberos database)."
        "9"  = "KDC_ERR_S_NOTIN_DB (Server not found in Kerberos database)."
        "10" = "KDC_ERR_SERVER_REVOKED (Server principal has been revoked)."
        "11" = "KDC_ERR_C_TGT_REVOKED (Client's TGT has been revoked)."
        "12" = "KDC_ERR_S_TGT_REVOKED (Server's TGT has been revoked)."
        "13" = "KDC_ERR_TGT_REVOKED (TGT for server has been revoked)."
        "14" = "KDC_ERR_C_NO_TGT (Client doesn't have a TGT or it's invalid)."
        "15" = "KDC_ERR_S_NO_TGT (Server doesn't have a TGT or it's invalid)."
        "16" = "KDC_ERR_ETYPE_NOTSUPP (Encryption type specified in the request is not supported)." # Duplicate of 5 in some docs, but distinct for some.
        "17" = "KDC_ERR_NEVER_VALID (Requested start time is in the future or ticket is not yet valid)."
        "18" = "KDC_ERR_POLICY (KDC policy prohibits this type of request)."
        "19" = "KDC_ERR_BADOPTION (Incorrect Kerberos options). Client sent invalid/unsupported options for the request."
        "20" = "KDC_ERR_NOT_PRIMARY (KDC is not the primary KDC for the requested realm)."
        "21" = "KDC_ERR_TGT_TIMESKEW (Ticket's timestamps are outside acceptable clock skew)."
        "22" = "KDC_ERR_TGT_DUPLICATE (Ticket presented is a duplicate of a previously issued ticket)."
        "23" = "KDC_ERR_TGT_NOTAUTH (Ticket is not yet authorized)."
        "24" = "KDC_ERR_PADATA_TYPE_NOSUPP (KDC has no support for pre-authentication data type). Client using unsupported pre-auth mechanism."
        "25" = "KDC_ERR_PREAUTH_REQUIRED (Additional pre-authentication is required). Often normal negotiation in initial AS-REQ/AS-REP exchange; KDC requests timestamp, etc."
        "26" = "KDC_ERR_SUMTYPE_NOSUPP (Checksum type is not supported by KDC)."
        "27" = "KDC_ERR_PRINCIPAL_UNKNOWN (Principal specified in the request is unknown)."
        "28" = "KDC_ERR_REQ_SALTY (Requested principal requires salt, but none was provided or it was incorrect)."
        "29" = "KRB_AP_ERR_BAD_INTEGRITY (Integrity check failed on AP-REQ or AP-REP). Indicates tampering or incorrect key."
        "30" = "KRB_AP_ERR_TKT_EXPIRED (Ticket in AP-REQ has expired)."
        "31" = "KRB_AP_ERR_TKT_NYV (Ticket in AP-REQ is not yet valid)."
        "32" = "KRB_AP_ERR_REPEAT (Replayed request detected in AP-REQ)."
        "33" = "KRB_AP_ERR_NOT_US (The ticket is for a different server principal)."
        "34" = "KRB_AP_ERR_BADMATCH (Ticket and authenticator don't match or are for different principals)."
        "35" = "KRB_AP_ERR_BADADDR (Client address in authenticator doesn't match ticket or request)."
        "36" = "KRB_AP_ERR_BADVERSION (Incorrect Kerberos protocol version in message)."
        "37" = "KRB_AP_ERR_MSG_TYPE (Invalid Kerberos message type)."
        "38" = "KRB_AP_ERR_MODIFIED (Message integrity check failed after modification)."
        "39" = "KRB_AP_ERR_BADORDER (Improper sequence of Kerberos messages)."
        "40" = "KRB_AP_ERR_BADKEYVER (Incorrect key version number for server)."
        "41" = "KRB_AP_ERR_NOKEY (Server has no key for the specified key version)."
        "42" = "KRB_AP_ERR_CMAC_UNDEF (Checksum type for message is undefined)."
        "43" = "KRB_AP_ERR_MACS_UNSUPP (Checksum type for message is unsupported)."
        "44" = "KRB_AP_ERR_INVALID_CRYPT (Encryption type for message is invalid)."
        "45" = "KRB_AP_ERR_REQ_TYPE (Requested message type is incorrect)."
        "46" = "KRB_AP_ERR_ERR_FIELD (Field in message contains an error)."
        "47" = "KRB_AS_REQ_INVALID (AS request is invalid)."
        "48" = "KRB_TGS_REQ_INVALID (TGS request is invalid)."
        "49" = "KRB_AP_REQ_INVALID (AP request is invalid)."
        "60" = "KDC_ERR_BAD_PRINCIPAL (Principal name is malformed or invalid)."
        "61" = "KDC_ERR_C_NOT_AUTHZ (Client is not authorized to use the service)."
        "62" = "KDC_ERR_DS_FULL (KDC's database is full)."
        "63" = "KDC_ERR_DS_NO_SUCH_ENTRY (Entry not found in KDC's database)."
        "64" = "KDC_ERR_DS_CANT_ACCESS (KDC cannot access its database)."
        "65" = "KDC_ERR_SVC_UNAVAILABLE (KDC service is unavailable)."
        "66" = "KRB_AP_ERR_NO_TKT (No ticket found in request)."
        "67" = "KRB_AP_ERR_AP_OPTIONS (AP options in request are invalid)."
        "68" = "KRB_AP_ERR_NO_USR_SPN (User's Service Principal Name (SPN) is missing)."
        "69" = "KDC_ERR_ETYPE_MISMATCH (Encryption type requested does not match the KDC's)."
        "70" = "KDC_ERR_GENERIC (Generic Kerberos error. Check other logs for details)."
        "71" = "KDC_ERR_CHECKSUM_MISMATCH (Checksum in message does not match)."
    }

    # SMB NT Status Codes (common authentication and file/share access failures)
    # For a comprehensive list, refer to Microsoft's NTSTATUS documentation.
    $smbStatusMap = @{
        # Authentication/Logon Failures
        "0xC000006D" = "STATUS_LOGON_FAILURE (Incorrect username/password or account restrictions like logon hours)."
        "0xC000006A" = "STATUS_WRONG_PASSWORD (Password expired or incorrect)."
        "0xC000006B" = "STATUS_NO_SUCH_USER (The specified account does not exist)."
        "0xC0000071" = "STATUS_ACCOUNT_RESTRICTION (Logon outside allowed hours, workstation restriction, etc.)."
        "0xC0000072" = "STATUS_ACCOUNT_DISABLED (The account is currently disabled)."
        "0xC0000073" = "STATUS_ACCOUNT_EXPIRED (The account has expired)."
        "0xC0000074" = "STATUS_INVALID_LOGON_HOURS (Attempted logon outside permitted hours)."
        "0xC0000075" = "STATUS_INVALID_WORKSTATION (User not allowed to logon from this workstation)."
        "0xC0000077" = "STATUS_PASSWORD_EXPIRED (User's password must change at next logon or has expired)."
        "0xC000007E" = "STATUS_ACCOUNT_LOCKED_OUT (Account is currently locked out)."
        "0xC0000133" = "STATUS_TIME_DIFFERENCE_AT_DC (Significant time difference between client and DC - similar to Kerberos clock skew)."
        "0xC000019C" = "STATUS_NO_LOGON_SERVERS (No Domain Controllers available to service the logon request)."
        "0xC0000234" = "STATUS_ACCOUNT_LOCKED_OUT (The user account has been automatically locked out because of too many invalid logon attempts)."
        "0xC0000224" = "STATUS_PASSWORD_RESTRICTION (Password complexity, length, or history requirement not met)."
        "0xC00002B4" = "STATUS_NTLM_BLOCKED (NTLM authentication is blocked by policy)."
        # File/Share Access Failures
        "0xC000000C" = "STATUS_INVALID_DEVICE_REQUEST (Often seen when trying to connect to a non-existent share/path)."
        "0xC000000F" = "STATUS_NO_SUCH_FILE (The specified file does not exist)."
        "0xC0000022" = "STATUS_ACCESS_DENIED (Insufficient permissions to access the resource/share/file)."
        "0xC0000034" = "STATUS_OBJECT_NAME_NOT_FOUND (The object name is not found. Similar to no such file/directory)."
        "0xC000007B" = "STATUS_BAD_NETWORK_PATH (The network path was not found, share may not exist or server is unreachable)."
        "0xC00000BB" = "STATUS_NOT_SUPPORTED (The request is not supported by the server/share)."
        "0xC0000040" = "STATUS_FILE_CLOSED (Attempt to access a file that is no longer open or was never opened)."
        "0xC00000C0" = "STATUS_NOT_A_DIRECTORY (Attempt to open a file as a directory, or vice-versa)."
        "0xC00000D0" = "STATUS_DISK_FULL (Disk space is full on the server)."
        "0xC0000002" = "STATUS_NOT_IMPLEMENTED (The requested operation is not implemented)." # Less common for shares
    }

    # DNS Response Codes (RCODEs from RFC 1035 and common extended RCODEs)
    # See RFC 1035 Section 4.1.1, and RFC 6891 (EDNS0) for extended RCODEs.
    $dnsRcodeMap = @{
        "0" = "NOERROR (No Error). The query was successful."
        "1" = "FORMERR (Format Error). The name server was unable to interpret the query."
        "2" = "SERVFAIL (Server Failure). The name server was unable to process this query due to a problem with the name server."
        "3" = "NXDOMAIN (Non-Existent Domain). The domain name referenced in the query does not exist."
        "4" = "NOTIMP (Not Implemented). The name server does not support the requested kind of query."
        "5" = "REFUSED (Query Refused). The name server refuses to perform the requested operation for policy reasons."
        "6" = "YXDOMAIN (Name Exists). Name exists when it should not (e.g., trying to create an existing name)."
        "7" = "YXRRSET (RRset Exists). RR set exists when it should not (e.g., trying to create an existing RR set)."
        "8" = "NXRRSET (RRset Does Not Exist). RR set that should exist does not (e.g., trying to delete a non-existent RR set)."
        "9" = "NOTAUTH (Not Authoritative / Not Authorized). The server is not authoritative for the zone, or the client is not authorized."
        "10" = "NOTZONE (Not In Zone). A name is not in the zone when it should be."
        # Extended RCODEs (via EDNS0) or other common issues
        "16" = "BADVERS / BADSIG (Bad OPT Version / Bad Signature). Often related to DNSSEC or EDNS0 issues."
        "17" = "BADKEY (Bad Key). DNSSEC-related security error."
        "18" = "BADTIME (Bad Time). DNSSEC-related timestamp error."
        "254" = "NODATA (No Data). Common for when a domain exists, but the requested record type (e.g., AAAA) does not."
        "900" = "DNS_ERROR_RCODE_SERVER_FAILURE (Windows-specific, similar to SERVFAIL)."
        "901" = "DNS_ERROR_RCODE_NAME_ERROR (Windows-specific, similar to NXDOMAIN)."
        "902" = "DNS_ERROR_RCODE_REFUSED (Windows-specific, similar to REFUSED)."
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
            # Including common SMB/NTLM authentication and share access errors
            $displayFilter = "kerberos.error_code ne 0 || smb.nt_status == 0xC000006D || smb.nt_status == 0xC000006A || smb.nt_status == 0xC000006B || smb.nt_status == 0xC0000071 || smb.nt_status == 0xC0000072 || smb.nt_status == 0xC0000073 || smb.nt_status == 0xC0000074 || smb.nt_status == 0xC0000075 || smb.nt_status == 0xC0000077 || smb.nt_status == 0xC000007E || smb.nt_status == 0xC0000133 || smb.nt_status == 0xC000019C || smb.nt_status == 0xC0000234 || smb.nt_status == 0xC0000224 || smb.nt_status == 0xC00002B4 || smb.nt_status == 0xC000000C || smb.nt_status == 0xC000000F || smb.nt_status == 0xC0000022 || smb.nt_status == 0xC0000034 || smb.nt_status == 0xC000007B || smb.nt_status == 0xC00000BB || smb.nt_status == 0xC0000040 || smb.nt_status == 0xC00000C0 || smb.nt_status == 0xC00000D0 || smb.nt_status == 0xC0000002"
            $outputFields += @("kerberos.error_code", "smb.nt_status")
            Write-Host "Searching for: Kerberos errors, common SMB/NTLM logon failures, and SMB/File Share access issues (e.g., Access Denied, File Not Found, Bad Path)." -ForegroundColor Yellow
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
            # Capture all DNS responses that are not NOERROR (rcode != 0) or are slow.
            $displayFilter = "dns.flags.response == 1 && dns.flags.rcode != 0 || dns.time > 0.1"
            $outputFields += @("dns.qry.name", "dns.flags.rcode", "dns.time")
            Write-Host "Searching for: DNS errors (e.g., NXDOMAIN, SERVFAIL, REFUSED) or responses slower than 100ms." -ForegroundColor Yellow
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
                $dnsRcode = $null
                $dnsTime = $null # New variable for DNS response time

                # Safely access properties based on AnalysisType
                if ($AnalysisType -eq "AuthenticationFailures") {
                    if ($row.PSObject.Properties.Name -contains "kerberos.error_code") { $kerr = $row."kerberos.error_code" }
                    if ($row.PSObject.Properties.Name -contains "smb.nt_status") { $smerr = $row."smb.nt_status" }
                } elseif ($AnalysisType -eq "DNS_Issues") {
                    if ($row.PSObject.Properties.Name -contains "dns.flags.rcode") { $dnsRcode = $row."dns.flags.rcode" }
                    if ($row.PSObject.Properties.Name -contains "dns.time") { $dnsTime = [double]::Parse($row."dns.time") }
                }
                
                # Build explanation for Kerberos errors
                if (-not [string]::IsNullOrWhiteSpace($kerr)) {
                    $explanation += $kerberosErrorMap[$kerr]
                }
                
                # Build explanation for SMB/NTLM errors
                if (-not [string]::IsNullOrWhiteSpace($smerr)) {
                    if (-not [string]::IsNullOrWhiteSpace($explanation)) { $explanation += "; " }
                    $explanation += $smbStatusMap[$smerr]
                }

                # Build explanation for DNS issues
                if (-not [string]::IsNullOrWhiteSpace($dnsRcode)) {
                    if ($dnsRcode -ne "0") { # If there's an actual DNS error code
                        if (-not [string]::IsNullOrWhiteSpace($explanation)) { $explanation += "; " }
                        $explanation += $dnsRcodeMap[$dnsRcode]
                    }
                    # Check for slow response even if RCODE is 0 (NOERROR)
                    if ($dnsRcode -eq "0" -and $dnsTime -ne $null -and $dnsTime -gt 0.1) {
                         if (-not [string]::IsNullOrWhiteSpace($explanation)) { $explanation += "; " }
                         $explanation += "Slow DNS Response (>${(0.1).ToString('F1')}s). Indicates potential network latency to DNS server or overloaded DNS server."
                    }
                }
                
                # Fallback if no specific explanation found for any captured code
                if ([string]::IsNullOrWhiteSpace($explanation)) {
                    if (-not [string]::IsNullOrWhiteSpace($kerr) -or -not [string]::IsNullOrWhiteSpace($smerr) -or (-not [string]::IsNullOrWhiteSpace($dnsRcode) -and $dnsRcode -ne "0") -or ($dnsTime -ne $null -and $dnsTime -gt 0.1)) {
                        $explanation = "No specific explanation available for this code in script or a known slow response."
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
