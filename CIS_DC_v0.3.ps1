
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

    Write-Host $text -ForegroundColor $color

    $text | Out-File -FilePath ".\$($output_file_name)" -Append

}

Output "ID|L|Text|Expected setting|Current setting|Result"

try {
#    secedit /export /cfg secpol.cfg
    $secpol = Get-Content secpol.cfg
} catch {
    Write-Host "Security policy export failed" -ForegroundColor Red
    Exit
}
Write-Host "Security policy exported"

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

Read-Host "Press enter to exit..."