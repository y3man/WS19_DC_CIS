
# $SID_NOONE = "`"`""

# $SID_ADMINISTRATORS = "*S-1-5-32-544"

# $SID_GUESTS = "*S-1-5-32-546"

# $SID_SERVICE = "*S-1-5-6"

# $SID_NETWORK_SERVICE = "*S-1-5-20"

# $SID_LOCAL_SERVICE = "*S-1-5-19"

# $SID_LOCAL_ACCOUNT = "*S-1-5-113"

# $SID_WINDOW_MANAGER_GROUP = "*S-1-5-90-0"

# $SID_REMOTE_DESKTOP_USERS = "*S-1-5-32-555"

# $SID_VIRTUAL_MACHINE = "*S-1-5-83-0"

# $SID_AUTHENTICATED_USERS = "*S-1-5-11"

# $SID_WDI_SYSTEM_SERVICE = "*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"

# $SID_BACKUP_OPERATORS = "S-1-5-32-551"

 

$output_file_name = "script_output.csv"

New-Item -Name $output_file_name -ItemType File -Force

function Output([string] $text, $color="White") {

    Write-Host $text -ForegroundColor $color

    $text | Out-File -FilePath ".\$($output_file_name)" -Append

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

function Get-PasswordPolicy([string] $settingName) {

    # Define a regular expression pattern
    $pattern = "(?<=\b$settingName\s*=\s*)\d+"

    # Use Select-String to find matches in the input string
    $matches = $secpol | Select-String -Pattern $pattern -AllMatches | ForEach-Object { $_.Matches.Value }

    # Check if any matches were found
    if ($matches.Count -gt 0) {
        # Return the first match (assuming unique settings)
        if ($matches.Count -gt 1) {
            return $matches[0]
        }
        return $matches
    } else {
        # Return a message indicating that the setting was not found
        return $false
    }
}

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

# Account lockout policies
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

# 1.2.3 (L1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'

$lockout_reset = Get-PasswordPolicy "ResetLockoutCount"
if ($lockout_reset -eq $false) {
    Output "1.2.3|L1|Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'|>=15|Not Found|NDF-NOK" Red
} elseif ([Int16]$lockout_reset -ge 15) {
    Output "1.2.3|L1|Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'|>=15|$($lockout_reset)|OK" Green
} else {
    Output "1.2.3|L1|Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'|>=15|$($lockout_reset)|NOK" Red
}



Write-Host "`nDone`nRemoving export files..."

try {

    Remove-Item .\secpol.cfg

} catch {

    Write-Host "Failed to remove secpol.cfg" -ForegroundColor Red

}

Read-Host "Press enter to exit..."