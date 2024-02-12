
$SID_NOONE = "`"`""

$SID_ADMINISTRATORS = "*S-1-5-32-544"

$SID_GUESTS = "*S-1-5-32-546"

$SID_SERVICE = "*S-1-5-6"

$SID_NETWORK_SERVICE = "*S-1-5-20"

$SID_LOCAL_SERVICE = "*S-1-5-19"

$SID_LOCAL_ACCOUNT = "*S-1-5-113"

$SID_WINDOW_MANAGER_GROUP = "*S-1-5-90-0"

$SID_REMOTE_DESKTOP_USERS = "*S-1-5-32-555"

$SID_VIRTUAL_MACHINE = "*S-1-5-83-0"

$SID_AUTHENTICATED_USERS = "*S-1-5-11"

$SID_WDI_SYSTEM_SERVICE = "*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"

$SID_BACKUP_OPERATORS = "*S-1-5-32-551"

$SID_ENTERPRISE_DOMAIN_CONTROLLERS= "*S-1-5-9"



$output_file_name = "script_output.csv"

New-Item -Name $output_file_name -ItemType File -Force

function Output([string] $text, $color="White") {

    $text | Out-File -FilePath ".\$($output_file_name)" -Append

    if ($text.length -gt 255) {
        $text = $text.Substring(0, 200)
        $text += "..."
    }
    Write-Host $text -ForegroundColor $color

}

Output "ID|L|Text|Expected setting|Current setting|Result"

try {
    secedit /export /cfg secpol.cfg
    $secpol = Get-Content secpol.cfg
} catch {
    Write-Host "Security policy export failed" -ForegroundColor Red
    Exit
}
Write-Host "Security policy exported"

try {
    auditpol /get /category:* > auditpol.txt
    $auditpol = Get-Content auditpol.txt
} catch {
    Write-Host "Audit policy export failed" -ForegroundColor Red
    Exit
}
Write-Host "Audit policy exported"

function Get-PasswordPolicy([string] $settingName) {

    # Define a regular expression pattern
    $pattern = "(?<=\b$settingName\s*=\s*)\d+"

    # Use Select-String to find matches in the input string
    $matches = $secpol | Select-String -Pattern $pattern -AllMatches | ForEach-Object { $_.Matches.Value }

    # Check if any matches were found
    if ($matches.Count -gt 0) {
        if ($matches.Count -gt 1) {
            return $matches[0]
        }
        return $matches
    } else {
        # Return a message indicating that the setting was not found
        return $false
    }
}

# Difference between 2 lists
function Compare-Lists([string[]] $list1, [string[]] $list2) {

    $list1 = $list1 | Where-Object { $list2 -notcontains $_ }
    $list2 = $list2 | Where-Object { $list1 -notcontains $_ }

    return $list1, $list2
}

function Get-RightAssignment([string] $role,
                             [string[]] $expected_values,
                             [string] $id,
                             [string] $l,
                             [string] $text,
                             [switch] $empty_ok=$false,
                             [switch] $iclude=$false) {
    $pattern = "(?<=\b$role\s*=\s*)\S+"

    $expected_values = $expected_values | ForEach-Object { $_.Trim() } | Sort-Object

    $matches = $secpol | Select-String -Pattern $pattern -AllMatches | ForEach-Object { $_.Matches.Value }
    try {
        $matches = $matches.Split(",")
    } catch { # no matches
        $matches = @()
    }
    if ($matches.Count -eq 0 -and $empty_ok -eq $true) {
        Output "$id|$l|$text|$expected_values|Not Found|NDF-OK" Green
        return
    } elseif($matches.Count -eq 0 -and $empty_ok -eq $false) {
        Output "$id|$l|$text|$expected_values|Not Found|NDF-NOK" Red
        return
    }
    $matches = $matches | ForEach-Object { $_.Trim() } | Sort-Object
    $diff = Compare-Lists $matches $expected_values

    $found_expected = $diff[1] | Sort-Object
    $found_unexpected = $diff[0] | Sort-Object

    #    write-host "wanted: $expected_values"
    #    write-host "found: $matches"
    #    write-host "found_expected: $found_expected"
    #    write-host "found_unexpected: $found_unexpected"
    if ($include -eq $true) {
        if ($found_expected.Count -eq $expected_values.Count) {
            Output "$id|$l|$text|$expected_values|$matches|OK" Green
        } else {
            Output "$id|$l|$text|$expected_values|$matches|NOK" Red
        }
    } else {
        if ($found_expected.Count -eq $expected_values.Count -and $found_unexpected.Count -eq 0) {
            Output "$id|$l|$text|$expected_values|$matches|OK" Green
        } else {
            Output "$id|$l|$text|$expected_values|$matches|NOK" Red
        }
    }
}

function Get-RegistryValue([string] $key,
                           [string] $value_name,
                           [string[]] $allowed_values,
                           [string] $id, [string] $l,
                           [string] $text,
                           [switch] $empty_ok=$false,
                           [switch] $reverse_values=$false) {
    try {
        $entry = Get-ItemPropertyValue -Path $key -Name $value_name -ErrorAction Stop
    } catch {
        if ($empty_ok -eq $true) {
            Output "$id|$l|$text|$allowed_values|Not Found|NDF-OK" Green
            return
        } else {
            Output "$id|$l|$text|$allowed_values|Not Found|NDF-NOK" Red
            return
        }
    }
    $found = $allowed_values -contains $entry
    if ($reverse_values -eq $false) {
        if ($found -eq $true) {
            Output "$id|$l|$text|$allowed_values|$entry|OK" Green
        } else {
            Output "$id|$l|$text|$allowed_values|$entry|NOK" Red
        }
    } else {
        if ($found -eq $true) {
            Output "$id|$l|$text|~$allowed_values|$entry|NOK" Red
        } else {
            Output "$id|$l|$text|~$allowed_values|$entry|OK" Green
        }
    }
}

function Get-AuditPolicy([string] $key,
                         [int[]] $desired,
                         [string] $id, [string] $l, [string] $text,
                         [switch] $include=$false) {
    $key_pattern = "  $key {2,}"
    $line = $auditpol | Select-String -Pattern $key_pattern
    $line = $line -replace "  $key {2,}", "$key,"
    $line = $line -split ","
    $setting = $line[1].Trim()

    $success = 0
    $failure = 0
    Write-Host "Setting: $setting"

    if ($setting -eq "Success and Failure") {
        $success = 1
        $failure = 1
    } elseif ($setting -eq "Success") {
        $success = 1
    } elseif ($setting -eq "Failure") {
        $failure = 1
    }
    $setting = ($success, $failure)

    if ($include -eq $true) {
        if ($desired[0] -eq 1 -and $success -eq 1) {
            Output "$id|$l|$text|$desired|$setting|OK" Green
            return
        } else {
            Output "$id|$l|$text|$desired|$setting|NOK" Red
            return
        }
        if ($desired[1] -eq 1 -and $failure -eq 1) {
            Output "$id|$l|$text|$desired|$setting|OK" Green
            return
        } else {
            Output "$id|$l|$text|$desired|$setting|NOK" Red
            return
        }
    } else {
        if ($success -eq $desired[0] -and $failure -eq $desired[1]) {
            Output "$id|$l|$text|$desired|$setting|OK" Green
        } else {
            Output "$id|$l|$text|$desired|$setting|NOK" Red
        }
    }
}

# --------------- Password policies ---------------

# 1.1.1 (L1) Ensure 'Enforce password history' is set to '24 or more password(s)'

$pw_history = Get-PasswordPolicy "PasswordHistorySize"
if ($pw_history -eq $false) {
    Output "1.1.1|L1|Ensure 'Enforce password history' is set to '24 or more password(s)'|>=24|Not Found|NDF-OK" Red
} elseif ([Int16]$pw_history -ge 24 -and [Int16]$pw_history -ne 0) {
    Output "1.1.1|L1|Ensure 'Enforce password history' is set to '24 or more password(s)'|>=24|$($pw_history)|OK" Green
} else {
    Output "1.1.1|L1|Ensure 'Enforce password history' is set to '24 or more password(s)'|>=24|$($pw_history)|NOK" Red
}

# 1.1.2 (L1) Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'

$pw_max_age = Get-PasswordPolicy "MaximumPasswordAge"
if ($pw_max_age -eq $false) {
    Output "1.1.2|L1|Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'|<=365|Not Found|NDF-NOK" Red
} elseif ([Int16]$pw_max_age -le 365 -and [Int16]$pw_max_age -ne 0) {
    Output "1.1.2|L1|Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'|<=365|$($pw_max_age)|OK" Green
} else {
    Output "1.1.2|L1|Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'|<=365|$($pw_max_age)|NOK" Red
}

# 1.1.3 (L1) Ensure 'Minimum password age' is set to '1 or more day(s)'

$pw_min_age = Get-PasswordPolicy "MinimumPasswordAge"
if ($pw_min_age -eq $false) {
    Output "1.1.3|L1|Ensure 'Minimum password age' is set to '1 or more day(s)'|>=1|Not Found|NDF-OK" Red
} elseif ([Int16]$pw_min_age -ge 1) {
    Output "1.1.3|L1|Ensure 'Minimum password age' is set to '1 or more day(s)'|>=1|$($pw_min_age)|OK" Green
} else {
    Output "1.1.3|L1|Ensure 'Minimum password age' is set to '1 or more day(s)'|>=1|$($pw_min_age)|NOK" Red
}

# 1.1.4 (L1) Ensure 'Minimum password length' is set to '14 or more character(s)'

$pw_min_length = Get-PasswordPolicy "MinimumPasswordLength"
if ($pw_min_length -eq $false) {
    Output "1.1.4|L1|Ensure 'Minimum password length' is set to '14 or more character(s)'|>=14|Not Found|NDF-NOK" Red
} elseif ([Int16]$pw_min_length -ge 14) {
    Output "1.1.4|L1|Ensure 'Minimum password length' is set to '14 or more character(s)'|>=14|$($pw_min_length)|OK" Green
} else {
    Output "1.1.4|L1|Ensure 'Minimum password length' is set to '14 or more character(s)'|>=14|$($pw_min_length)|NOK" Red
}

# 1.1.5 (L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled'

$pw_complexity = Get-PasswordPolicy "PasswordComplexity"
if ($pw_complexity -eq $false) {
    Output "1.1.5|L1|Ensure 'Password must meet complexity requirements' is set to 'Enabled'|1|Not Found|NDF-OK" Red
} elseif ($pw_complexity -eq 1) {
    Output "1.1.5|L1|Ensure 'Password must meet complexity requirements' is set to 'Enabled'|1|$($pw_complexity)|OK" Green
} else {
    Output "1.1.5|L1|Ensure 'Password must meet complexity requirements' is set to 'Enabled'|1|$($pw_complexity)|NOK" Red
}

# 1.1.6 (L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled'

$pw_reversible = Get-PasswordPolicy "ClearTextPassword"
if ($pw_reversible -eq $false) {
    Output "1.1.6|L1|Ensure 'Store passwords using reversible encryption' is set to 'Disabled'|0|Not Found|NDF-OK" Red
} elseif ($pw_reversible -eq 0) {
    Output "1.1.6|L1|Ensure 'Store passwords using reversible encryption' is set to 'Disabled'|0|$($pw_reversible)|OK" Green
} else {
    Output "1.1.6|L1|Ensure 'Store passwords using reversible encryption' is set to 'Disabled'|0|$($pw_reversible)|NOK" Red
}

# --------------- Account lockout policies ---------------

# 1.2.1 (L1) Ensure 'Account lockout duration' is set to '15 or more minute(s)'

$lockout_duration = Get-PasswordPolicy "LockoutDuration"
if ($lockout_duration -eq $false) {
    Output "1.2.1|L1|Ensure 'Account lockout duration' is set to '15 or more minute(s)'|>=15|Not Found|NDF-NOK" Red
} elseif ([Int16]$lockout_duration -ge 15) {
    Output "1.2.1|L1|Ensure 'Account lockout duration' is set to '15 or more minute(s)'|>=15|$($lockout_duration)|OK" Green
} else {
    Output "1.2.1|L1|Ensure 'Account lockout duration' is set to '15 or more minute(s)'|>=15|$($lockout_duration)|NOK" Red
}

# 1.2.2 (L1) Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0'

$lockout_threshold = Get-PasswordPolicy "LockoutBadCount"
if ($lockout_threshold -eq $false) {
    Output "1.2.2|L1|Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0'|<=10|Not Found|NDF-NOK" Red
} elseif ([Int16]$lockout_threshold -le 10 -and [Int16]$lockout_threshold -ne 0) {
    Output "1.2.2|L1|Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0'|<=10|$($lockout_threshold)|OK" Green
} else {
    Output "1.2.2|L1|Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0'|<=10|$($lockout_threshold)|NOK" Red
}

# 1.2.3 (L1) Ensure 'Allow Administrator account lockout' is set to 'Enabled'

$lockout_admin = Get-PasswordPolicy "LockoutBadCount"
if ($lockout_admin -eq $false) {
    Output "1.2.3|L1|Ensure 'Allow Administrator account lockout' is set to 'Enabled'|1|Not Found|NDF-OK" Red
} elseif ($lockout_admin -eq 1) {
    Output "1.2.3|L1|Ensure 'Allow Administrator account lockout' is set to 'Enabled'|1|$($lockout_admin)|OK" Green
} else {
    Output "1.2.3|L1|Ensure 'Allow Administrator account lockout' is set to 'Enabled'|1|$($lockout_admin)|NOK" Red
}

# 1.2.4 (L1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'

$lockout_reset = Get-PasswordPolicy "ResetLockoutCount"
if ($lockout_reset -eq $false) {
    Output "1.2.4|L1|Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'|>=15|Not Found|NDF-NOK" Red
} elseif ([Int16]$lockout_reset -ge 15) {
    Output "1.2.4|L1|Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'|>=15|$($lockout_reset)|OK" Green
} else {
    Output "1.2.4|L1|Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'|>=15|$($lockout_reset)|NOK" Red
}

# --------------- User rights assignment ---------------

#2.2.1 (L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'
Get-RightAssignment "SeTrustedCredManAccessPrivilege" ($SID_NOONE) "2.2.1" "L1" "Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'" -empty_ok

# 2.2.2 (L1) Ensure 'Access this computer from the network' is set
# to 'Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS' (DC only)
Get-RightAssignment "SeNetworkLogonRight" ($SID_ADMINISTRATORS, $SID_AUTHENTICATED_USERS, $SID_ENTERPRISE_DOMAIN_CONTROLLERS) "2.2.2" "L1" "Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS'"

# 2.2.3 (L1) Ensure 'Access this computer from the network' is set
# to 'Administrators, Authenticated Users' (MS only)
# Get-RightAssignment "SeNetworkLogonRight" ($SID_ADMINISTRATORS, $SID_AUTHENTICATED_USERS) "2.2.3" "L1" "Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users'"

# 2.2.4 (L1) Ensure 'Act as part of the operating system' is set to 'No One'
Get-RightAssignment "SeTcbPrivilege" ($SID_NOONE) "2.2.4" "L1" "Ensure 'Act as part of the operating system' is set to 'No One'" -empty_ok

# 2.2.5 (L1) Ensure 'Add workstations to domain' is set to 'Administrators' (DC only)
Get-RightAssignment "SeMachineAccountPrivilege" ($SID_ADMINISTRATORS) "2.2.5" "L1" "Ensure 'Add workstations to domain' is set to 'Administrators'"

# 2.2.6 (L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
Get-RightAssignment "SeIncreaseQuotaPrivilege" ($SID_ADMINISTRATORS, $SID_LOCAL_SERVICE, $SID_NETWORK_SERVICE) "2.2.6" "L1" "Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'"

# 2.2.7 (L1) Ensure 'Allow log on locally' is set to 'Administrators'
Get-RightAssignment "SeInteractiveLogonRight" ($SID_ADMINISTRATORS) "2.2.7" "L1" "Ensure 'Allow log on locally' is set to 'Administrators, Backup Operators'"

# 2.2.8 (L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators' (DC only)
Get-RightAssignment "SeRemoteInteractiveLogonRight" ($SID_ADMINISTRATORS) "2.2.8" "L1" "Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators'"

# 2.2.9 (L1) Ensure 'Allow log on through Remote Desktop
#Services' is set to 'Administrators, Remote Desktop Users' (MSonly)
# Get-RightAssignment "SeRemoteInteractiveLogonRight" ($SID_ADMINISTRATORS, $SID_REMOTE_DESKTOP_USERS) "2.2.9" "L1" "Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'" -empty_ok

# 2.2.10 (L1) Ensure 'Back up files and directories' is set to 'Administrators'
Get-RightAssignment "SeBackupPrivilege" ($SID_ADMINISTRATORS) "2.2.10" "L1" "Ensure 'Back up files and directories' is set to 'Administrators'"

# 2.2.11 (L1) Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'
Get-RightAssignment "SeSystemtimePrivilege" ($SID_ADMINISTRATORS, $SID_LOCAL_SERVICE) "2.2.11" "L1" "Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'"

# 2.2.12 (L1) Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'
Get-RightAssignment "SeTimeZonePrivilege" ($SID_ADMINISTRATORS, $SID_LOCAL_SERVICE) "2.2.12" "L1" "Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'"

# 2.2.13 (L1) Ensure 'Create a pagefile' is set to 'Administrators'
Get-RightAssignment "SeCreatePagefilePrivilege" ($SID_ADMINISTRATORS) "2.2.13" "L1" "Ensure 'Create a pagefile' is set to 'Administrators'"

# 2.2.14 (L1) Ensure 'Create a token object' is set to 'No One'
Get-RightAssignment "SeCreateTokenPrivilege" ($SID_NOONE) "2.2.14" "L1" "Ensure 'Create a token object' is set to 'No One'" -empty_ok

# 2.2.15 (L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
Get-RightAssignment "SeCreateGlobalPrivilege" ($SID_ADMINISTRATORS, $SID_LOCAL_SERVICE, $SID_NETWORK_SERVICE, $SID_SERVICE) "2.2.15" "L1" "Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"

# 2.2.16 (L1) Ensure 'Create permanent shared objects' is set to 'No One'
Get-RightAssignment "SeCreatePermanentPrivilege" ($SID_NOONE) "2.2.16" "L1" "Ensure 'Create permanent shared objects' is set to 'No One'" -empty_ok

# 2.2.17 (L1) Ensure 'Create symbolic links' is set to 'Administrators' (DC only)
Get-RightAssignment "SeCreateSymbolicLinkPrivilege" ($SID_ADMINISTRATORS) "2.2.17" "L1" "Ensure 'Create symbolic links' is set to 'Administrators'"

# 2.2.18 (L1) Ensure 'Create symbolic links' is set to
#'Administrators, NT VIRTUAL MACHINE\Virtual Machines' (MSonly)
# Get-RightAssignment "SeCreateSymbolicLinkPrivilege" ($SID_ADMINISTRATORS, $SID_VIRTUAL_MACHINE) "2.2.18" "L1" "Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines'"

# 2.2.19 (L1) Ensure 'Debug programs' is set to 'Administrators'
Get-RightAssignment "SeDebugPrivilege" ($SID_ADMINISTRATORS) "2.2.19" "L1" "Ensure 'Debug programs' is set to 'Administrators'"

# 2.2.20 (L1) Ensure 'Deny access to this computer from the network' to include 'Guests' (DC only)
Get-RightAssignment "SeDenyNetworkLogonRight" ($SID_GUESTS) "2.2.20" "L1" "Ensure 'Deny access to this computer from the network' to include 'Guests'" -include

# 2.2.21 (L1) Ensure 'Deny access to this computer from the
# network' to include 'Guests, Local account and member of Administrators group' (MS only)
# Get-RightAssignment "SeDenyNetworkLogonRight" ($SID_GUESTS, $SID_LOCAL_ACCOUNT) "2.2.21" "L1" "Ensure 'Deny access to this computer from the network' to include 'Guests, Local account and member of Administrators group'" -include

# 2.2.22 (L1) Ensure 'Deny log on as a batch job' to include 'Guests'
Get-RightAssignment "SeDenyBatchLogonRight" ($SID_GUESTS) "2.2.22" "L1" "Ensure 'Deny log on as a batch job' to include 'Guests'" -include

# 2.2.23 (L1) Ensure 'Deny log on as a service' to include 'Guests'
Get-RightAssignment "SeDenyServiceLogonRight" ($SID_GUESTS) "2.2.23" "L1" "Ensure 'Deny log on as a service' to include 'Guests'" -include

# 2.2.24 (L1) Ensure 'Deny log on locally' to include 'Guests'
Get-RightAssignment "SeDenyInteractiveLogonRight" ($SID_GUESTS) "2.2.24" "L1" "Ensure 'Deny log on locally' to include 'Guests'" -include

# 2.2.25 (L1) Ensure 'Deny log on through Remote Desktop Services' to include 'Guests' (DC only)
Get-RightAssignment "SeDenyRemoteInteractiveLogonRight" ($SID_GUESTS) "2.2.25" "L1" "Ensure 'Deny log on through Remote Desktop Services' to include 'Guests'" -include

# 2.2.26 (L1) Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests, Local account' (MS only)
#Get-RightAssignment "SeDenyRemoteInteractiveLogonRight" ($SID_GUESTS, $SID_LOCAL_ACCOUNT) "2.2.26" "L1" "Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests, Local account'"

# 2.2.27 (L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'Administrators' (DC only)
Get-RightAssignment "SeEnableDelegationPrivilege" ($SID_ADMINISTRATORS) "2.2.27" "L1" "Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'Administrators'"

# 2.2.28 (L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One' (MS only)
#Get-RightAssignment "SeEnableDelegationPrivilege" ($SID_NOONE) "2.2.28" "L1" "Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'" -empty_ok

# 2.2.29 (L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'
Get-RightAssignment "SeRemoteShutdownPrivilege" ($SID_ADMINISTRATORS) "2.2.29" "L1" "Ensure 'Force shutdown from a remote system' is set to 'Administrators'"

# 2.2.30 (L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'
Get-RightAssignment "SeAuditPrivilege" ($SID_LOCAL_SERVICE, $SID_NETWORK_SERVICE) "2.2.30" "L1" "Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'"

# 2.2.31 (L1) Ensure 'Impersonate a client after authentication' is
#set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' (DC only)
Get-RightAssignment "SeImpersonatePrivilege" ($SID_ADMINISTRATORS, $SID_LOCAL_SERVICE, $SID_NETWORK_SERVICE, $SID_SERVICE) "2.2.31" "L1" "Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"

# 2.2.32 (L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE,
#SERVICE' and (when the Web Server (IIS) Role with Web Services Role Service is installed) 'IIS_IUSRS' (MS only)
#Get-RightAssignment "SeImpersonatePrivilege" ($SID_ADMINISTRATORS, $SID_LOCAL_SERVICE, $SID_NETWORK_SERVICE, $SID_SERVICE) "2.2.31" "L1" "Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"

# 2.2.33 (L1) Ensure 'Increase scheduling priority' is set to
#'Administrators, Window Manager\Window Manager Group'
Get-RightAssignment "SeIncreaseBasePriorityPrivilege" ($SID_ADMINISTRATORS, $SID_WINDOW_MANAGER_GROUP) "2.2.33" "L1" "Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group'"

# 2.2.34 (L1) Ensure 'Load and unload device drivers' is set to 'Administrators'
Get-RightAssignment "SeLoadDriverPrivilege" ($SID_ADMINISTRATORS) "2.2.34" "L1" "Ensure 'Load and unload device drivers' is set to 'Administrators'"

# 2.2.35 (L1) Ensure 'Lock pages in memory' is set to 'No One'
Get-RightAssignment "SeLockMemoryPrivilege" ($SID_NOONE) "2.2.35" "L1" "Ensure 'Lock pages in memory' is set to 'No One'" -empty_ok

# 2.2.36 (L2) Ensure 'Log on as a batch job' is set to 'Administrators' (DC Only)
Get-RightAssignment "SeBatchLogonRight" ($SID_ADMINISTRATORS) "2.2.36" "L2" "Ensure 'Log on as a batch job' is set to 'Administrators'"

# 2.2.37 (L1) Ensure 'Manage auditing and security log' is set to
#'Administrators' and (when Exchange is running in the environment) 'Exchange Servers' (DC only)
Get-RightAssignment "SeSecurityPrivilege" ($SID_ADMINISTRATORS) "2.2.37" "L1" "Ensure 'Manage auditing and security log' is set to 'Administrators' (and possibly Exchange Servers)"

# 2.2.38 (L1) Ensure 'Manage auditing and security log' is set to 'Administrators' (MS only)
#Get-RightAssignment "SeSecurityPrivilege" ($SID_ADMINISTRATORS) "2.2.38" "L1" "Ensure 'Manage auditing and security log' is set to 'Administrators'"

# 2.2.39 (L1) Ensure 'Modify an object label' is set to 'No One'
Get-RightAssignment "SeRelabelPrivilege" ($SID_NOONE) "2.2.39" "L1" "Ensure 'Modify an object label' is set to 'No One'" -empty_ok

# 2.2.40 (L1) Ensure 'Modify firmware environment values' is set to 'Administrators'
Get-RightAssignment "SeSystemEnvironmentPrivilege" ($SID_ADMINISTRATORS) "2.2.40" "L1" "Ensure 'Modify firmware environment values' is set to 'Administrators'"

# 2.2.41 (L1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators'
Get-RightAssignment "SeManageVolumePrivilege" ($SID_ADMINISTRATORS) "2.2.41" "L1" "Ensure 'Perform volume maintenance tasks' is set to 'Administrators'"

# 2.2.42 (L1) Ensure 'Profile single process' is set to 'Administrators'
Get-RightAssignment "SeProfileSingleProcessPrivilege" ($SID_ADMINISTRATORS) "2.2.42" "L1" "Ensure 'Profile single process' is set to 'Administrators'"

# 2.2.43 (L1) Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'
Get-RightAssignment "SeSystemProfilePrivilege" ($SID_ADMINISTRATORS, $SID_WDI_SYSTEM_SERVICE) "2.2.43" "L1" "Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'"

# 2.2.44 (L1) Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'
Get-RightAssignment "SeAssignPrimaryTokenPrivilege" ($SID_LOCAL_SERVICE, $SID_NETWORK_SERVICE) "2.2.44" "L1" "Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'"

# 2.2.45 (L1) Ensure 'Restore files and directories' is set to 'Administrators'
Get-RightAssignment "SeRestorePrivilege" ($SID_ADMINISTRATORS) "2.2.45" "L1" "Ensure 'Restore files and directories' is set to 'Administrators'"

# 2.2.46 (L1) Ensure 'Shut down the system' is set to 'Administrators, LOCAL SERVICE'
Get-RightAssignment "SeShutdownPrivilege" ($SID_ADMINISTRATORS, $SID_LOCAL_SERVICE) "2.2.46" "L1" "Ensure 'Shut down the system' is set to 'Administrators, LOCAL SERVICE'"

# 2.2.47 (L1) Ensure 'Synchronize directory service data' is set to 'No One' (DC only)
Get-RightAssignment "SeSyncAgentPrivilege" ($SID_NOONE) "2.2.47" "L1" "Ensure 'Synchronize directory service data' is set to 'No One'" -empty_ok

# 2.2.48 (L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators'
Get-RightAssignment "SeTakeOwnershipPrivilege" ($SID_ADMINISTRATORS) "2.2.48" "L1" "Ensure 'Take ownership of files or other objects' is set to 'Administrators'"

# --------------- Security options ---------------

# 2.3.1.1 (L1) Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'
Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "NoConnectedUser" ("3") "2.3.1.1" "L1" "Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'"

# 2.3.1.3 (L1) Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse" ("1") "2.3.1.3" "L1" "Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'"

# 2.3.1.4 (L1) Configure 'Accounts: Rename administrator account'
$admin_name_line = $secpol | Select-String -Pattern "NewAdministratorName" -AllMatches
if ($admin_name_line -match "= `"Administrator`"$") {
    Output "2.3.1.4|L1|Configure 'Accounts: Rename administrator account'|~Administrator|Administrator|NOK" Red
} else {
    Output "2.3.1.4|L1|Configure 'Accounts: Rename administrator account'|~Administrator|$admin_name_line|OK" Green
}

# 2.3.1.5 (L1) Configure 'Accounts: Rename guest account
$guest_name_line = $secpol | Select-String -Pattern "NewGuestName" -AllMatches
if ($guest_name_line -match "= `"Guest`"$") {
    Output "2.3.1.5|L1|Configure 'Accounts: Rename guest account'|~Guest|Guest|NOK" Red
} else {
    Output "2.3.1.5|L1|Configure 'Accounts: Rename guest account'|~Guest|$guest_name_line|OK" Green
}

# --------------- Audit settings ---------------

# 2.3.2.1 (L1) Ensure 'Audit: Force audit policy subcategory settings
#(Windows Vista or later) to override audit policy category settings' is set to 'Enabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "SCENoApplyLegacyAuditPolicy" ("1") "2.3.2.1" "L1" "Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'" -empty_ok

# 2.3.2.2 (L1) Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "CrashOnAuditFail" ("0") "2.3.2.2" "L1" "Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'" -empty_ok

# --------------- Devices ---------------

# 2.3.4.1 (L1) Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
Get-RegistryValue "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "AllocateDASD" ("0") "2.3.4.1" "L1" "Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'" -empty_ok

# 2.3.4.2 (L1) Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
Get-RegistryValue "HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" "AddPrinterDrivers" ("1") "2.3.4.2" "L1" "Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'" -empty_ok

# --------------- Domain controller ---------------

# 2.3.5.1 (L1) Ensure 'Domain controller: Allow server operators to schedule tasks' is set to 'Disabled' (DC only)
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "SubmitControl" ("0") "2.3.5.1" "L1" "Ensure 'Domain controller: Allow server operators to schedule tasks' is set to 'Disabled'" -empty_ok

# 2.3.5.2 (L1) Ensure 'Domain controller: Allow vulnerable Netlogon secure channel connections' is set to 'Not Configured' (DC Only)
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "VulnerableChannelAllowList" @() "2.3.5.2" "L1" "Ensure 'Domain controller: Allow vulnerable Netlogon secure channel connections' is set to 'Not Configured'" -empty_ok

# 2.3.5.3 (L1) Ensure 'Domain controller: LDAP server channel binding token requirements' is set to 'Always' (DC Only)
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" "LdapEnforceChannelBinding" ("2") "2.3.5.3" "L1" "Ensure 'Domain controller: LDAP server channel binding token requirements' is set to 'Always'"

# 2.3.5.4 (L1) Ensure 'Domain controller: LDAP server signing requirements' is set to 'Require signing' (DC only)
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" "LDAPServerIntegrity" ("2") "2.3.5.4" "L1" "Ensure 'Domain controller: LDAP server signing requirements' is set to 'Require signing'"

# 2.3.5.5 (L1) Ensure 'Domain controller: Refuse machine account password changes' is set to 'Disabled' (DC only)
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RefusePasswordChange" ("0") "2.3.5.5" "L1" "Ensure 'Domain controller: Refuse machine account password changes' is set to 'Disabled'" -empty_ok

# --------------- Domain member ---------------

# 2.3.6.1 (L1) Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RequireSignOrSeal" ("1") "2.3.6.1" "L1" "Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'" -empty_ok

# 2.3.6.2 (L1) Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "SealSecureChannel" ("1") "2.3.6.2" "L1" "Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'" -empty_ok

# 2.3.6.3 (L1) Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "SignSecureChannel" ("1") "2.3.6.3" "L1" "Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'" -empty_ok

# 2.3.6.4 (L1) Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "DisablePasswordChange" ("0") "2.3.6.4" "L1" "Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'" -empty_ok

# 2.3.6.5 (L1) Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "MaximumPasswordAge" (1..30) "2.3.6.5" "L1" "Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'" -empty_ok

# 2.3.6.6 (L1) Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RequireStrongKey" ("1") "2.3.6.6" "L1" "Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'" -empty_ok

# --------------- Interactive logon ---------------

# 2.3.7.1 (L1) Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD" ("0") "2.3.7.1" "L1" "Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'" -empty_ok

# 2.3.7.2 (L1) Ensure 'Interactive logon: Don't display last signed-in' is set to 'Enabled'
Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DontDisplayLastUserName" ("1") "2.3.7.2" "L1" "Ensure 'Interactive logon: Don't display last signed-in' is set to 'Enabled'"

# 2.3.7.3 (L1) Ensure 'Interactive logon: Machine inactivity limit' is
#set to '900 or fewer second(s), but not 0'
Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs" (1..900) "2.3.7.3" "L1" "Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'"

# 2.3.7.4 (L1) Configure 'Interactive logon: Message text for users attempting to log on'
try {
    $msg_text = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeText" -ErrorAction Stop
} catch {
    $msg_text = $false
} finally {
    if ($msg_text -eq $false -or $msg_text.Trim().length -eq 0) {
        Output "2.3.7.4|L1|Configure 'Interactive logon: Message text for users attempting to log on'|~|Not Found|NDF-NOK" Red
    } else {
        Output "2.3.7.4|L1|Configure 'Interactive logon: Message text for users attempting to log on'|~|$msg_text|OK" Green
    }
}

# 2.3.7.5 (L1) Configure 'Interactive logon: Message title for users attempting to log on'
try {
    $msg_title = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeCaption" -ErrorAction Stop
} catch {
    $msg_title = $false
} finally {
    if ($msg_title -eq $false -or $msg_title.Trim().length -eq 0) {
        Output "2.3.7.5|L1|Configure 'Interactive logon: Message title for users attempting to log on'|~|Not Found|NDF-NOK" Red
    } else {
        Output "2.3.7.5|L1|Configure 'Interactive logon: Message title for users attempting to log on'|~|$msg_title|OK" Green
    }
}

# 2.3.7.7 (L1) Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'
Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "PasswordExpiryWarning" (5..14) "2.3.7.7" "L1" "Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'"

# 2.3.7.9 (L1) Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher
Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "ScRemoveOption" (1..3) "2.3.7.9" "L1" "Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher"

# --------------- Microsoft network client ---------------

# 2.3.8.1 (L1) Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature" ("1") "2.3.8.1" "L1" "Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'"

# 2.3.8.2 (L1) Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnableSecuritySignature" ("1") "2.3.8.2" "L1" "Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'"

# 2.3.8.3 (L1) Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnablePlainTextPassword" ("0") "2.3.8.3" "L1" "Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'"

# --------------- Microsoft network server ---------------

# 2.3.9.1 (L1) Ensure 'Microsoft network server: Amount of idle time
#required before suspending session' is set to '15 or fewer minute(s)'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "AutoDisconnect" (1..15) "2.3.9.1" "L1" "Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)'"

# 2.3.9.2 (L1) Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "RequireSecuritySignature" ("1") "2.3.9.2" "L1" "Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'"

# 2.3.9.3 (L1) Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "EnableSecuritySignature" ("1") "2.3.9.3" "L1" "Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'"

# 2.3.9.4 (L1) Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "EnableForcedLogOff" ("1") "2.3.9.4" "L1" "Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'" -empty_ok

# --------------- Network access ---------------

# 2.3.10.1 (L1) Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "TurnOffAnonymousBlock" ("1") "2.3.10.1" "L1" "Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'" -empty_ok

# 2.3.10.4 (L2) Ensure 'Network access: Do not allow storage of
#passwords and credentials for network authentication' is set to 'Enabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "DisableDomainCreds" ("1") "2.3.10.4" "L2" "Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'"

# 2.3.10.5 (L1) Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "EveryoneIncludesAnonymous" ("0") "2.3.10.5" "L1" "Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'" -empty_ok

# 2.3.10.6 (L1) Configure 'Network access: Named Pipes that can be accessed anonymously' (DC only)
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "NullSessionPipes" @() "2.3.10.6" "L1" "Configure 'Network access: Named Pipes that can be accessed anonymously'" -empty_ok

# 2.3.10.8 (L1) Configure 'Network access: Remotely accessible registry paths' is configured
$expected_paths = ("System\CurrentControlSet\Control\ProductOptions", "System\CurrentControlSet\Control\Server Applications", "Software\Microsoft\Windows NT\CurrentVersion")
try {
    $reg_paths = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths" -Name "Machine" -ErrorAction Stop
} catch {
    $reg_paths = $false
} finally {
    if ($reg_paths -eq $false -or $reg_paths.Count -eq 0) {
        Output "2.3.10.8|L1|Configure 'Network access: Remotely accessible registry paths' is configured|$expected_paths|Not Found|NDF-NOK" Red
    } else {
        Output "2.3.10.8|L1|Configure 'Network access: Remotely accessible registry paths' is configured|$expected_paths|$reg_paths|MAN"
    }
}

# 2.3.10.9 (L1) Configure 'Network access: Remotely accessible registry paths and sub-paths' is configured
$expected_paths = ("System\CurrentControlSet\Control\Print\Printers", "System\CurrentControlSet\Services\Eventlog", "Software\Microsoft\OLAP Server", "Software\Microsoft\Windows NT\CurrentVersion\Print", "Software\Microsoft\Windows NT\CurrentVersion\Windows", "System\CurrentControlSet\Control\ContentIndex", "System\CurrentControlSet\Control\Terminal Server", "System\CurrentControlSet\Control\Terminal Server\UserConfig", "System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration", "Software\Microsoft\Windows NT\CurrentVersion\Perflib", "System\CurrentControlSet\Services\SysmonLog")
try {
    $reg_paths = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths" -Name "Machine" -ErrorAction Stop
} catch {
    $reg_paths = $false
} finally {
    if ($reg_paths -eq $false -or $reg_paths.Count -eq 0) {
        Output "2.3.10.9|L1|Configure 'Network access: Remotely accessible registry paths and sub-paths' is configured|$expected_paths|Not Found|NDF-NOK" Red
    } else {
        Output "2.3.10.9|L1|Configure 'Network access: Remotely accessible registry paths and sub-paths' is configured|$expected_paths|$reg_paths|MAN"
    }
}

# 2.3.10.10 (L1) Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "RestrictNullSessAccess" ("1") "2.3.10.10" "L1" "Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'" -empty_ok

# 2.3.10.12 (L1) Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "NullSessionShares" @() "2.3.10.12" "L1" "Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'" -empty_ok

# 2.3.10.13 (L1) Ensure 'Network access: Sharing and security
#model for local accounts' is set to 'Classic - local users authenticate as themselves'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "ForceGuest" ("0") "2.3.10.13" "L1" "Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'" -empty_ok

# --------------- Network security ---------------

# 2.3.11.1 (L1) Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "UseMachineId" ("1") "2.3.11.1" "L1" "Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'" -empty_ok

# 2.3.11.2 (L1) Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "AllowNullSessionFallback" ("0") "2.3.11.2" "L1" "Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'" -empty_ok

# 2.3.11.3 (L1) Ensure 'Network Security: Allow PKU2U
#authentication requests to this computer to use online identities' is set to 'Disabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u" "AllowOnlineID" ("0") "2.3.11.3" "L1" "Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'" -empty_ok

# 2.3.11.4 (L1) Ensure 'Network security: Configure encryption
#types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'
Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" "SupportedEncryptionTypes" ("2147483640") "2.3.11.4" "L1" "Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'"

# 2.3.11.5 (L1) Ensure 'Network security: Do not store LAN
#Manager hash value on next password change' is set to 'Enabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "NoLMHash" ("1") "2.3.11.5" "L1" "Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'" -empty_ok

# 2.3.11.6 (L1) Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'
$force_logoff = $secpol | Select-String -Pattern "ForceLogoffWhenHourExpire"
if ($force_logoff -match " = 1") {
    Output "2.3.11.6|L1|Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'|$force_logoff|1|OK" Green
} else {
    Output "2.3.11.6|L1|Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'|$force_logoff|1|NOK" Red
}

# 2.3.11.7 (L1) Ensure 'Network security: LAN Manager
#authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel" ("5") "2.3.11.7" "L1" "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'"

#2.3.11.8 (L1) Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" "LDAPClientIntegrity" ("1", "2") "2.3.11.8" "L1" "Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher"

# 2.3.11.9 (L1) Ensure 'Network security: Minimum session security
#for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NTLMMinClientSec" ("537395200") "2.3.11.9" "L1" "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"

# 2.3.11.10 (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is
#set to 'Require NTLMv2 session security, Require 128-bit encryption'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NTLMMinServerSec" ("537395200") "2.3.11.10" "L1" "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"

# --------------- Shutdown ---------------

# 2.3.13.1 (L1) Ensure 'Shutdown: Allow system to be shut down
#without having to log on' is set to 'Disabled'
Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ShutdownWithoutLogon" ("0") "2.3.13.1" "L1" "Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'" -empty_ok

# --------------- System objects ---------------

# 2.3.15.1 (L1) Ensure 'System objects: Require case insensitivity
#for non-Windows subsystems' is set to 'Enabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" "ObCaseInsensitive" ("1") "2.3.15.1" "L1" "Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'" -empty_ok

# 2.3.15.2 (L1) Ensure 'System objects: Strengthen default
#permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "ProtectionMode" ("1") "2.3.15.2" "L1" "Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'" -empty_ok

# --------------- User Account Control ---------------

# 2.3.17.1 (L1) Ensure 'User Account Control: Admin Approval
#Mode for the Built-in Administrator account' is set to 'Enabled'
Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "FilterAdministratorToken" ("1") "2.3.17.1" "L1" "Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'"

# 2.3.17.2 (L1) Ensure 'User Account Control: Behavior of the
#elevation prompt for administrators in Admin Approval Mode' is
#set to 'Prompt for consent on the secure desktop' or higher
Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" ("2", "5") "2.3.17.2" "L1" "Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop' or higher"

# 2.3.17.3 (L1) Ensure 'User Account Control: Behavior of the
#elevation prompt for standard users' is set to 'Automatically deny elevation requests'
Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorUser" ("0") "2.3.17.3" "L1" "Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'"

# 2.3.17.4 (L1) Ensure 'User Account Control: Detect application
#installations and prompt for elevation' is set to 'Enabled'
Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableInstallerDetection" ("1") "2.3.17.4" "L1" "Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'"

# 2.3.17.5 (L1) Ensure 'User Account Control: Only elevate
#UIAccess applications that are installed in secure locations' is set to 'Enabled'
Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableSecureUIAPaths" ("1") "2.3.17.5" "L1" "Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'" -empty_ok

# 2.3.17.6 (L1) Ensure 'User Account Control: Run all
#administrators in Admin Approval Mode' is set to 'Enabled'
Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA" ("1") "2.3.17.6" "L1" "Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'" -empty_ok

# 2.3.17.7 (L1) Ensure 'User Account Control: Switch to the secure
#desktop when prompting for elevation' is set to 'Enabled'
Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop" ("1") "2.3.17.7" "L1" "Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'" -empty_ok

# 2.3.17.8 (L1) Ensure 'User Account Control: Virtualize file and
#registry write failures to per-user locations' is set to 'Enabled'
Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableVirtualization" ("1") "2.3.17.8" "L1" "Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'" -empty_ok

# --------------- System services ---------------

# 5.1 (L1) Ensure 'Print Spooler (Spooler)' is set to 'Disabled' (DC only)
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler" "Start" ("4") "5.1" "L1" "Ensure 'Print Spooler (Spooler)' is set to 'Disabled'"

# --------------- Firewall (domain) ---------------

# 9.1.1 (L1) Ensure 'Windows Firewall: Domain: Firewall state' is set
#to 'On (recommended)'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "EnableFirewall" ("1") "9.1.1" "L1" "Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'" -empty_ok

# 9.1.2 (L1) Ensure 'Windows Firewall: Domain: Inbound
#connections' is set to 'Block (default)'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "DefaultInboundAction" ("1") "9.1.2" "L1" "Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'" -empty_ok

# 9.1.3 (L1) Ensure 'Windows Firewall: Domain: Outbound
#connections' is set to 'Allow (default)'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "DefaultOutboundAction" ("0") "9.1.3" "L1" "Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'" -empty_ok

# 9.1.4 (L1) Ensure 'Windows Firewall: Domain: Settings: Display a
#notification' is set to 'No'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "DisableNotifications" ("1") "9.1.4" "L1" "Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'"

# 9.1.5 (L1) Ensure 'Windows Firewall: Domain: Logging: Name' is
#set to '%SystemRoot%\System32\logfiles\firewall\domainfw.log'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogFilePath" ("%SystemRoot%\System32\logfiles\firewall\domainfw.log") "9.1.5" "L1" "Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\domainfw.log'"

# 9.1.6 (L1) Ensure 'Windows Firewall: Domain: Logging: Size limit
#(KB)' is set to '16,384 KB or greater'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogFileSize" (16384..99999) "9.1.6" "L1" "Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'"

# 9.1.7 (L1) Ensure 'Windows Firewall: Domain: Logging: Log
#dropped packets' is set to 'Yes'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogDroppedPackets" ("1") "9.1.7" "L1" "Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'"

# 9.1.8 (L1) Ensure 'Windows Firewall: Domain: Logging: Log
#successful connections' is set to 'Yes'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogSuccessfulConnections" ("1") "9.1.8" "L1" "Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'"

# --------------- Firewall (private) ---------------

# 9.2.1 (L1) Ensure 'Windows Firewall: Private: Firewall state' is set
#to 'On (recommended)'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "EnableFirewall" ("1") "9.2.1" "L1" "Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'" -empty_ok

# 9.2.2 (L1) Ensure 'Windows Firewall: Private: Inbound
#connections' is set to 'Block (default)'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "DefaultInboundAction" ("1") "9.2.2" "L1" "Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'" -empty_ok

# 9.2.3 (L1) Ensure 'Windows Firewall: Private: Outbound
#connections' is set to 'Allow (default)'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "DefaultOutboundAction" ("0") "9.2.3" "L1" "Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'" -empty_ok

# 9.2.4 (L1) Ensure 'Windows Firewall: Private: Settings: Display a
#notification' is set to 'No'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "DisableNotifications" ("1") "9.2.4" "L1" "Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'"

# 9.2.5 (L1) Ensure 'Windows Firewall: Private: Logging: Name' is
#set to '%SystemRoot%\System32\logfiles\firewall\privatefw.log'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogFilePath" ("%SystemRoot%\System32\logfiles\firewall\privatefw.log") "9.2.5" "L1" "Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\privatefw.log'"

# 9.2.6 (L1) Ensure 'Windows Firewall: Private: Logging: Size limit
#(KB)' is set to '16,384 KB or greater'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogFileSize" (16384..99999) "9.2.6" "L1" "Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'"

# 9.2.7 (L1) Ensure 'Windows Firewall: Private: Logging: Log
#dropped packets' is set to 'Yes'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogDroppedPackets" ("1") "9.2.7" "L1" "Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'"

# 9.2.8 (L1) Ensure 'Windows Firewall: Private: Logging: Log
#successful connections' is set to 'Yes'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogSuccessfulConnections" ("1") "9.2.8" "L1" "Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'"

# --------------- Firewall (public) ---------------

# 9.3.1 (L1) Ensure 'Windows Firewall: Public: Firewall state' is set
#to 'On (recommended)'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "EnableFirewall" ("1") "9.3.1" "L1" "Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'" -empty_ok

# 9.3.2 (L1) Ensure 'Windows Firewall: Public: Inbound connections'
#is set to 'Block (default)'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "DefaultInboundAction" ("1") "9.3.2" "L1" "Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'" -empty_ok

# 9.3.3 (L1) Ensure 'Windows Firewall: Public: Outbound
#connections' is set to 'Allow (default)'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "DefaultOutboundAction" ("0") "9.3.3" "L1" "Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'" -empty_ok

# 9.3.4 (L1) Ensure 'Windows Firewall: Public: Settings: Display a
#notification' is set to 'No'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "DisableNotifications" ("1") "9.3.4" "L1" "Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'"

# 9.3.5 (L1) Ensure 'Windows Firewall: Public: Settings: Apply local
#firewall rules' is set to 'No'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "AllowLocalPolicyMerge" ("0") "9.3.5" "L1" "Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'"

# 9.3.6 (L1) Ensure 'Windows Firewall: Public: Settings: Apply local
#connection security rules' is set to 'No'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "AllowLocalIPsecPolicyMerge" ("0") "9.3.6" "L1" "Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'"

# 9.3.7 (L1) Ensure 'Windows Firewall: Public: Logging: Name' is
#set to '%SystemRoot%\System32\logfiles\firewall\publicfw.log'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogFilePath" ("%SystemRoot%\System32\logfiles\firewall\publicfw.log") "9.3.7" "L1" "Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\publicfw.log'"

# 9.3.8 (L1) Ensure 'Windows Firewall: Public: Logging: Size limit
#(KB)' is set to '16,384 KB or greater'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogFileSize" (16384..99999) "9.3.8" "L1" "Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'"

# 9.3.9 (L1) Ensure 'Windows Firewall: Public: Logging: Log
#dropped packets' is set to 'Yes'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogDroppedPackets" ("1") "9.3.9" "L1" "Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'"

# 9.3.10 (L1) Ensure 'Windows Firewall: Public: Logging: Log
#successful connections' is set to 'Yes'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogSuccessfulConnections" ("1") "9.3.10" "L1" "Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'"

# --------------- Audit policy ---------------

# 17.1.1 (L1) Ensure 'Audit Credential Validation' is set to 'Success and Failure'
Get-AuditPolicy "Credential Validation" (1,1) "17.1.1" "L1" "Ensure 'Audit Credential Validation' is set to 'Success and Failure'"

# 17.1.2 (L1) Ensure 'Audit Kerberos Authentication Service' is set to 'Success and Failure' (DC Only)
Get-AuditPolicy "Kerberos Authentication Service" (1,1) "17.1.2" "L1" "Ensure 'Audit Kerberos Authentication Service' is set to 'Success and Failure'"

# 17.1.3 (L1) Ensure 'Audit Kerberos Service Ticket Operations' is set to 'Success and Failure' (DC Only)
Get-AuditPolicy "Kerberos Service Ticket Operations" (1,1) "17.1.3" "L1" "Ensure 'Audit Kerberos Service Ticket Operations' is set to 'Success and Failure'"

# 17.2.1 (L1) Ensure 'Audit Application Group Management' is set to 'Success and Failure'
Get-AuditPolicy "Application Group Management" (1,1) "17.2.1" "L1" "Ensure 'Audit Application Group Management' is set to 'Success and Failure'"

# 17.2.2 (L1) Ensure 'Audit Computer Account Management' is set to include 'Success' (DC only)
Get-AuditPolicy "Computer Account Management" (1,0) "17.2.2" "L1" "Ensure 'Audit Computer Account Management' is set to include 'Success'" -include

# 17.2.3 (L1) Ensure 'Audit Distribution Group Management' is set to include 'Success' (DC only)
Get-AuditPolicy "Distribution Group Management" (1,0) "17.2.3" "L1" "Ensure 'Audit Distribution Group Management' is set to include 'Success'" -include

# 17.2.4 (L1) Ensure 'Audit Other Account Management Events' is set to include 'Success' (DC only)
Get-AuditPolicy "Other Account Management Events" (1,0) "17.2.4" "L1" "Ensure 'Audit Other Account Management Events' is set to include 'Success'" -include

# 17.2.5 (L1) Ensure 'Audit Security Group Management' is set to include 'Success'
Get-AuditPolicy "Security Group Management" (1,0) "17.2.5" "L1" "Ensure 'Audit Security Group Management' is set to include 'Success'" -include

# 17.2.6 (L1) Ensure 'Audit User Account Management' is set to 'Success and Failure'
Get-AuditPolicy "User Account Management" (1,1) "17.2.6" "L1" "Ensure 'Audit User Account Management' is set to 'Success and Failure'"

# 17.3.1 (L1) Ensure 'Audit PNP Activity' is set to include 'Success'
Get-AuditPolicy "PNP Activity" (1,0) "17.3.1" "L1" "Ensure 'Audit PNP Activity' is set to include 'Success'" -include

# 17.3.2 (L1) Ensure 'Audit Process Creation' is set to include 'Success'
Get-AuditPolicy "Process Creation" (1,0) "17.3.2" "L1" "Ensure 'Audit Process Creation' is set to include 'Success'" -include

# 17.4.1 (L1) Ensure 'Audit Directory Service Access' is set to include 'Failure' (DC only)
Get-AuditPolicy "Directory Service Access" (0,1) "17.4.1" "L1" "Ensure 'Audit Directory Service Access' is set to include 'Failure'" -include

# 17.4.2 (L1) Ensure 'Audit Directory Service Changes' is set to include 'Success' (DC only)
Get-AuditPolicy "Directory Service Changes" (1,0) "17.4.2" "L1" "Ensure 'Audit Directory Service Changes' is set to include 'Success'" -include

# 17.5.1 (L1) Ensure 'Audit Account Lockout' is set to include 'Failure'
Get-AuditPolicy "Account Lockout" (0,1) "17.5.1" "L1" "Ensure 'Audit Account Lockout' is set to include 'Failure'" -include

# 17.5.2 (L1) Ensure 'Audit Group Membership' is set to include 'Success'
Get-AuditPolicy "Group Membership" (1,0) "17.5.2" "L1" "Ensure 'Audit Group Membership' is set to include 'Success'" -include

# 17.5.3 (L1) Ensure 'Audit Logoff' is set to include 'Success'
Get-AuditPolicy "Logoff" (1,0) "17.5.3" "L1" "Ensure 'Audit Logoff' is set to include 'Success'" -include

# 17.5.4 (L1) Ensure 'Audit Logon' is set to 'Success and Failure'
Get-AuditPolicy "Logon" (1,1) "17.5.4" "L1" "Ensure 'Audit Logon' is set to 'Success and Failure'"

# 17.5.5 (L1) Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'
Get-AuditPolicy "Other Logon/Logoff Events" (1,1) "17.5.5" "L1" "Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'"

# 17.5.6 (L1) Ensure 'Audit Special Logon' is set to include 'Success'
Get-AuditPolicy "Special Logon" (1,0) "17.5.6" "L1" "Ensure 'Audit Special Logon' is set to include 'Success'" -include

# 17.6.1 (L1) Ensure 'Audit Detailed File Share' is set to include 'Failure'
Get-AuditPolicy "Detailed File Share" (0,1) "17.6.1" "L1" "Ensure 'Audit Detailed File Share' is set to include 'Failure'" -include

# 17.6.2 (L1) Ensure 'Audit File Share' is set to 'Success and Failure'
Get-AuditPolicy "File Share" (1,1) "17.6.2" "L1" "Ensure 'Audit File Share' is set to 'Success and Failure'"

# 17.6.3 (L1) Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'
Get-AuditPolicy "Other Object Access Events" (1,1) "17.6.3" "L1" "Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'"

# 17.6.4 (L1) Ensure 'Audit Removable Storage' is set to 'Success and Failure'
Get-AuditPolicy "Removable Storage" (1,1) "17.6.4" "L1" "Ensure 'Audit Removable Storage' is set to 'Success and Failure'"

# 17.7.1 (L1) Ensure 'Audit Audit Policy Change' is set to include 'Success'
Get-AuditPolicy "Audit Policy Change" (1,0) "17.7.1" "L1" "Ensure 'Audit Audit Policy Change' is set to include 'Success'" -include

# 17.7.2 (L1) Ensure 'Audit Authentication Policy Change' is set to include 'Success'
Get-AuditPolicy "Authentication Policy Change" (1,0) "17.7.2" "L1" "Ensure 'Audit Authentication Policy Change' is set to include 'Success'" -include

# 17.7.3 (L1) Ensure 'Audit Authorization Policy Change' is set to include 'Success'
Get-AuditPolicy "Authorization Policy Change" (1,0) "17.7.3" "L1" "Ensure 'Audit Authorization Policy Change' is set to include 'Success'" -include

# 17.7.4 (L1) Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'
Get-AuditPolicy "MPSSVC Rule-Level Policy Change" (1,1) "17.7.4" "L1" "Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'"

# 17.7.5 (L1) Ensure 'Audit Other Policy Change Events' is set to include 'Failure'
Get-AuditPolicy "Other Policy Change Events" (0,1) "17.7.5" "L1" "Ensure 'Audit Other Policy Change Events' is set to include 'Failure'" -include

# 17.8.1 (L1) Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'
Get-AuditPolicy "Sensitive Privilege Use" (1,1) "17.8.1" "L1" "Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'"

# 17.9.1 (L1) Ensure 'Audit IPsec Driver' is set to 'Success and Failure'
Get-AuditPolicy "IPsec Driver" (1,1) "17.9.1" "L1" "Ensure 'Audit IPsec Driver' is set to 'Success and Failure'"

# 17.9.2 (L1) Ensure 'Audit Other System Events' is set to 'Success and Failure'
Get-AuditPolicy "Other System Events" (1,1) "17.9.2" "L1" "Ensure 'Audit Other System Events' is set to 'Success and Failure'"

# 17.9.3 (L1) Ensure 'Audit Security State Change' is set to include 'Success'
Get-AuditPolicy "Security State Change" (1,0) "17.9.3" "L1" "Ensure 'Audit Security State Change' is set to include 'Success'" -include

# 17.9.4 (L1) Ensure 'Audit Security System Extension' is set to include 'Success'
Get-AuditPolicy "Security System Extension" (1,0) "17.9.4" "L1" "Ensure 'Audit Security System Extension' is set to include 'Success'" -include

# 17.9.5 (L1) Ensure 'Audit System Integrity' is set to 'Success and Failure'
Get-AuditPolicy "System Integrity" (1,1) "17.9.5" "L1" "Ensure 'Audit System Integrity' is set to 'Success and Failure'"

# --------------- Administrative templates ---------------

# ------------------- Personalization -------------------

# 18.1.1.1 (L1) Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenCamera" ("1") "18.1.1.1" "L1" "Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'"

# 18.1.1.2 (L1) Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenSlideshow" ("1") "18.1.1.2" "L1" "Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'"

# 18.1.2.2 (L1) Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" "AllowInputPersonalization" ("1") "18.1.2.2" "L1" "Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'"

# 18.1.3 (L2) Ensure 'Allow Online Tips' is set to 'Disabled'
Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "AllowOnlineTips" ("1") "18.1.3" "L2" "Ensure 'Allow Online Tips' is set to 'Disabled'"

# ------------------- MS Security Guide -------------------

# 18.4.2 (L1) Ensure 'Configure RPC packet level privacy setting for
#incoming connections' is set to 'Enabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Print" "RpcAuthnLevelPrivacyEnabled" ("1") "18.4.2" "L1" "Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'" -empty_ok

# 18.4.3 (L1) Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" "Start" ("0") "18.4.3" "L1" "Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver'" -empty_ok

# 18.4.4 (L1) Ensure 'Configure SMB v1 server' is set to 'Disabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1" ("0") "18.4.4" "L1" "Ensure 'Configure SMB v1 server' is set to 'Disabled'" -empty_ok

# 18.4.5 (L1) Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "DisableExceptionChainValidation" ("0") "18.4.5" "L1" "Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'"

# 18.4.6 (L1) Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" "NodeType" ("1") "18.4.6" "L1" "Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node'"

# 18.4.7 (L1) Ensure 'WDigest Authentication' is set to 'Disabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential" ("0") "18.4.7" "L1" "Ensure 'WDigest Authentication' is set to 'Disabled'" -empty_ok

# 18.5.1 (L1) Ensure 'MSS: (AutoAdminLogon) Enable Automatic
#Logon (not recommended)' is set to 'Disabled'
Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon" ("0") "18.5.1" "L1" "Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'" -empty_ok

# 18.5.2 (L1) Ensure 'MSS: (DisableIPSourceRouting IPv6) IP
#source routing protection level (protects against packet spoofing)'
#is set to 'Enabled: Highest protection, source routing is completely disabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisableIPSourceRouting" ("2") "18.5.2" "L1" "Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'"

# 18.5.3 (L1) Ensure 'MSS: (DisableIPSourceRouting) IP source
#routing protection level (protects against packet spoofing)' is set
#to 'Enabled: Highest protection, source routing is completely disabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "DisableIPSourceRouting" ("2") "18.5.3" "L1" "Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'"

# 18.5.4 (L1) Ensure 'MSS: (EnableICMPRedirect) Allow ICMP
#redirects to override OSPF generated routes' is set to 'Disabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "EnableICMPRedirect" ("0") "18.5.4" "L1" "Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'"

# 18.5.5 (L2) Ensure 'MSS: (KeepAliveTime) How often keep-alive
#packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes (recommended)'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "KeepAliveTime" ("300000") "18.5.5" "L2" "Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes (recommended)'"

# 18.5.6 (L1) Ensure 'MSS: (NoNameReleaseOnDemand) Allow the
#computer to ignore NetBIOS name release requests except from
#WINS servers' is set to 'Enabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" "NoNameReleaseOnDemand" ("1") "18.5.6" "L1" "Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'" -empty_ok

# 18.5.7 (L2) Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP
#to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "PerformRouterDiscovery" ("0") "18.5.7" "L2" "Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'"

# 18.5.8 (L1) Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL
#search mode (recommended)' is set to 'Enabled'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "SafeDllSearchMode" ("1") "18.5.8" "L1" "Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'" -empty_ok

# 18.5.9 (L1) Ensure 'MSS: (ScreenSaverGracePeriod) The time in
#seconds before the screen saver grace period expires (0
#recommended)' is set to 'Enabled: 5 or fewer seconds'
Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "ScreenSaverGracePeriod" (0..5) "18.5.9" "L1" "Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'"

# 18.5.10 (L2) Ensure 'MSS: (TcpMaxDataRetransmissions IPv6)
#How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "TcpMaxDataRetransmissions" ("3") "18.5.10" "L2" "Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'"

# 18.5.11 (L2) Ensure 'MSS: (TcpMaxDataRetransmissions) How
#many times unacknowledged data is retransmitted' is set to 'Enabled: 3'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "TcpMaxDataRetransmissions" ("3") "18.5.11" "L2" "Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'"

# 18.5.12 (L1) Ensure 'MSS: (WarningLevel) Percentage threshold
#for the security event log at which the system will generate a
#warning' is set to 'Enabled: 90% or less'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security" "WarningLevel" (0..90) "18.5.12" "L1" "Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'"

# --------------- DNS client ---------------

# 18.6.4.1 (L1) Ensure 'Configure NetBIOS settings' is set to
#'Enabled: Disable NetBIOS name resolution on public networks'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableNetbios" ("1") "18.6.4.1" "L1" "Ensure 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name resolution on public networks'" -empty_ok

# 18.6.4.2 (L1) Ensure 'Turn off multicast name resolution' is set to 'Enabled'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" ("0") "18.6.4.2" "L1" "Ensure 'Turn off multicast name resolution' is set to 'Enabled'"

# --------------- Fonts ---------------

# 18.6.5.1 (L2) Ensure 'Enable Font Providers' is set to 'Disabled'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableFontProviders" ("0") "18.6.5.1" "L2" "Ensure 'Enable Font Providers' is set to 'Disabled'"

# --------------- LanMan workstation ---------------

# 18.6.8.1 (L1) Ensure 'Enable insecure guest logons' is set to 'Disabled'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" "AllowInsecureGuestAuth" ("0") "18.6.8.1" "L1" "Ensure 'Enable insecure guest logons' is set to 'Disabled'"

# --------------- Link-Layer Topology Discovery ---------------

# 18.6.9.1 (L2) Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "AllowLLTDIOOnDomain" ("0") "18.6.9.1" "L2" "Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'" -empty_ok
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "AllowLLTDIOOnPublicNet" ("0") "18.6.9.1" "L2" "Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'" -empty_ok
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "EnableLLTDIO" ("0") "18.6.9.1" "L2" "Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'" -empty_ok
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "ProhibitLLTDIOOnPrivateNet" ("0") "18.6.9.1" "L2" "Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'" -empty_ok

# 18.6.9.2 (L2) Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "AllowRspndrOnDomain" ("0") "18.6.9.2" "L2" "Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'" -empty_ok
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "AllowRspndrOnPublicNet" ("0") "18.6.9.2" "L2" "Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'" -empty_ok
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "EnableRspndr" ("0") "18.6.9.2" "L2" "Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'" -empty_ok
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "ProhibitRspndrOnPrivateNet" ("0") "18.6.9.2" "L2" "Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'" -empty_ok

# --------------- Peer Name Resolution Protocol ---------------

# 18.6.10.2 (L2) Ensure 'Turn off Microsoft Peer-to-Peer Networking
#Services' is set to 'Enabled'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" "Disabled" ("1") "18.6.10.2" "L2" "Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'"

# --------------- Windows Defender Firewall ---------------

# 18.6.11.2 (L1) Ensure 'Prohibit installation and configuration of
#Network Bridge on your DNS domain network' is set to 'Enabled'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" "NC_AllowNetBridge_NLA" ("0") "18.6.11.2" "L1" "Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'"

# 18.6.11.3 (L1) Ensure 'Prohibit use of Internet Connection
#Sharing on your DNS domain network' is set to 'Enabled'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" "NC_ShowSharedAccessUI" ("0") "18.6.11.3" "L1" "Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'"

# 18.6.11.4 (L1) Ensure 'Require domain users to elevate when
#setting a network's location' is set to 'Enabled'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" "NC_StdDomainUserSetLocation" ("1") "18.6.11.4" "L1" "Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'"

# --------------- Network Provider ---------------

# 18.6.14.1 (L1) Ensure 'Hardened UNC Paths' is set to 'Enabled,
#with "Require Mutual Authentication" and "Require Integrity" set
#for all NETLOGON and SYSVOL shares'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" "\\*\NETLOGON" ("RequireMutualAuthentication=1, RequireIntegrity=1") "18.6.14.1" "L1" "Ensure 'Hardened UNC Paths' is set to 'Enabled, with 'Require Mutual Authentication' and 'Require Integrity' set for all NETLOGON and SYSVOL shares'"

# --------------- TCP/IP settings ---------------

# 18.6.19.2.1 (L2) Disable IPv6 (Ensure TCPIP6 Parameter
#'DisabledComponents' is set to '0xff (255)')
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" "DisabledComponents" ("255") "18.6.19.2.1" "L2" "Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)'"

# 18.6.20.1 (L2) Ensure 'Configuration of wireless settings using
#Windows Connect Now' is set to 'Disabled'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" "EnableRegistrars" ("0") "18.6.20.1" "L2" "Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'"
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" "DisableUPnPRegistrar" ("0") "18.6.20.1" "L2" "Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'"
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" "DisableInBand802DOT11Registrar" ("0") "18.6.20.1" "L2" "Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'"
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" "DisableFlashConfigRegistrar" ("0") "18.6.20.1" "L2" "Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'"
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" "DisableWPDRegistrar" ("0") "18.6.20.1" "L2" "Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'"

# 18.6.20.2 (L2) Ensure 'Prohibit access of the Windows Connect
#Now wizards' is set to 'Enabled'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" "DisableWcnUi" ("1") "18.6.20.2" "L2" "Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'"

# 18.6.21.1 (L1) Ensure 'Minimize the number of simultaneous
#connections to the Internet or a Windows Domain' is set to
#'Enabled: 3 = Prevent Wi-Fi when on Ethernet'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" "fMinimizeConnections" ("3") "18.6.21.1" "L1" "Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet'"

# --------------- Printers ---------------

# 18.7.1 (L1) Ensure 'Allow Print Spooler to accept client
#connections' is set to 'Disabled'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "RegisterSpoolerRemoteRpcEndPoint" ("2") "18.7.1" "L1" "Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled'"

# 18.7.2 (L1) Ensure 'Configure Redirection Guard' is set to
#'Enabled: Redirection Guard Enabled'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "RedirectionguardPolicy" ("1") "18.7.2" "L1" "Ensure 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled'"

# 18.7.3 (L1) Ensure 'Configure RPC connection settings: Protocol
#to use for outgoing RPC connections' is set to 'Enabled: RPC over TCP'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" "RpcUseNamedPipeProtocol" ("0") "18.7.3" "L1" "Ensure 'Configure RPC connection settings: Protocol to use for outgoing RPC connections' is set to 'Enabled: RPC over TCP'"

# 18.7.4 (L1) Ensure 'Configure RPC connection settings: Use
#authentication for outgoing RPC connections' is set to 'Enabled: Default'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" "RpcAuthentication" ("1") "18.7.4" "L1" "Ensure 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is set to 'Enabled: Default'"

# 18.7.5 (L1) Ensure 'Configure RPC listener settings: Protocols to
#allow for incoming RPC connections' is set to 'Enabled: RPC over TCP'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" "RpcProtocols" ("0") "18.7.5" "L1" "Ensure 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP'"

# 18.7.6 (L1) Ensure 'Configure RPC listener settings:
#Authentication protocol to use for incoming RPC connections:' is
#set to 'Enabled: Negotiate' or higher
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" "ForceKerberosForRpc" ("2") "18.7.6" "L1" "Ensure 'Configure RPC listener settings: Authentication protocol to use for incoming RPC connections:' is set to 'Enabled: Negotiate' or higher" -empty_ok

# 18.7.7 (L1) Ensure 'Configure RPC over TCP port' is set to
#'Enabled: 0'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" "RpcTcpPort" ("0") "18.7.7" "L1" "Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0'"

# 18.7.8 (L1) Ensure 'Limits print driver installation to
#Administrators' is set to 'Enabled'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "RestrictDriverInstallationToAdministrators" ("1") "18.7.8" "L1" "Ensure 'Limits print driver installation to Administrators' is set to 'Enabled'" -empty_ok

# 18.7.9 (L1) Ensure 'Manage processing of Queue-specific files' is
#set to 'Enabled: Limit Queue-specific files to Color profiles'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "CopyFilesPolicy" ("1") "18.7.9" "L1" "Ensure 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue-specific files to Color profiles'" -empty_ok

# 18.7.10 (L1) Ensure 'Point and Print Restrictions: When installing
#drivers for a new connection' is set to 'Enabled: Show warning
#and elevation prompt'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" "NoWarningNoElevationOnInstall" ("0") "18.7.10" "L1" "Ensure 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt'" -empty_ok

# 18.7.11 (L1) Ensure 'Point and Print Restrictions: When updating
#drivers for an existing connection' is set to 'Enabled: Show
#warning and elevation prompt'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" "UpdatePromptSettings" ("0") "18.7.11" "L1" "Ensure 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt'" -empty_ok

# --------------- Start menu and taskbar ---------------

# 18.8.1.1 (L2) Ensure 'Turn off notifications network usage' is set
#to 'Enabled'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoCloudApplicationNotification" ("1") "18.8.1.1" "L2" "Ensure 'Turn off notifications network usage' is set to 'Enabled'"

# --------------- System ---------------

# 18.9.3.1 (L1) Ensure 'Include command line in process creation
#events' is set to 'Enabled'
Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled" ("1") "18.9.3.1" "L1" "Ensure 'Include command line in process creation events' is set to 'Enabled'"

# 18.9.4.1 (L1) Ensure 'Encryption Oracle Remediation' is set to
#'Enabled: Force Updated Clients'
Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" "AllowEncryptionOracle" ("0") "18.9.4.1" "L1" "Ensure 'Encryption Oracle Remediation' is set to 'Enabled: Force Updated Clients'"

# 18.9.4.2 (L1) Ensure 'Remote host allows delegation of non-
#exportable credentials' is set to 'Enabled'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" "AllowProtectedCreds" ("1") "18.9.4.2" "L1" "Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'"

# 18.9.5.1 (NG) Ensure 'Turn On Virtualization Based Security' is
#set to 'Enabled'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "EnableVirtualizationBasedSecurity" ("1") "18.9.5.1" "NG" "Ensure 'Turn On Virtualization Based Security' is set to 'Enabled'"

# 18.9.5.2 (NG) Ensure 'Turn On Virtualization Based Security:
#Select Platform Security Level' is set to 'Secure Boot' or higher
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "RequirePlatformSecurityFeatures" ("3") "18.9.5.2" "NG" "Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot' or higher"

# 18.9.5.3 (NG) Ensure 'Turn On Virtualization Based Security:
#Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "HypervisorEnforcedCodeIntegrity" ("1") "18.9.5.3" "NG" "Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'"

# 18.9.5.4 (NG) Ensure 'Turn On Virtualization Based Security:
#Require UEFI Memory Attributes Table' is set to 'True (checked)'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "HVCIMATRequired" ("1") "18.9.5.4" "NG" "Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)'"

# 18.9.5.6 (NG) Ensure 'Turn On Virtualization Based Security:
#Credential Guard Configuration' is set to 'Disabled' (DC Only)
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "LsaCfgFlags" ("0") "18.9.5.6" "NG" "Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Disabled' (DC Only)" -empty_ok

# 18.9.5.7 (NG) Ensure 'Turn On Virtualization Based Security:
#Secure Launch Configuration' is set to 'Enabled'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "ConfigureSystemGuardLaunch" ("1") "18.9.5.7" "NG" "Ensure 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled'"

# --------------- Device installation ---------------

# 18.9.7.2 (L1) Ensure 'Prevent device metadata retrieval from the
#Internet' is set to 'Enabled'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" "PreventDeviceMetadataFromNetwork" ("1") "18.9.7.2" "L1" "Ensure 'Prevent device metadata retrieval from the Internet' is set to 'Enabled'"

# --------------- Early Launch Antimalware ---------------

# 18.9.13.1 (L1) Ensure 'Boot-Start Driver Initialization Policy' is set
#to 'Enabled: Good, unknown and bad but critical'
Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" "DriverLoadPolicy" ("3") "18.9.13.1" "L1" "Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'"

# --------------- Group policy ---------------

# 18.9.19.2 (L1) Ensure 'Configure registry policy processing: Do
#not apply during periodic background processing' is set to 'Enabled: FALSE'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" "NoBackgroundPolicy" ("0") "18.9.19.2" "L1" "Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'"

# 18.9.19.3 (L1) Ensure 'Configure registry policy processing:
#Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" "NoGPOListChanges" ("0") "18.9.19.3" "L1" "Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'"

# 18.9.19.4 (L1) Ensure 'Continue experiences on this device' is set to 'Disabled'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableCdp" ("0") "18.9.19.4" "L1" "Ensure 'Continue experiences on this device' is set to 'Disabled'"

# 18.9.19.5 (L1) Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'
Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DisableBkGndGroupPolicy" ("0") "18.9.19.5" "L1" "Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'"

# --------------- Internet communication settings ---------------

Write-Host "`nDone`nRemoving export files..."

#try {
#
#    Remove-Item .\secpol.cfg
#
#} catch {
#
#    Write-Host "Failed to remove secpol.cfg" -ForegroundColor Red
#
#}

#try {
#
#    Remove-Item .\auditpol.txt
#
#} catch {
#
#    Write-Host "Failed to remove auditpol.txt" -ForegroundColor Red
#
#}

Read-Host "Press enter to exit..."