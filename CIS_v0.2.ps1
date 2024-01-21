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

$SID_BACKUP_OPERATORS = "S-1-5-32-551"

 

$output_file_name = "script_output.csv"

New-Item -Name $output_file_name -ItemType File -Force

function Output([string] $text, $color="White") {

    Write-Host $text -ForegroundColor $color

    $text | Out-File -FilePath ".\$($output_file_name)" -Append

}

 

# "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "EnableFirewall" "1"

function GetRegEntry([string] $path, [string] $key, [string] $desired_value) {

    try {

        $entry = Get-ItemPropertyValue -Path $path -Name $key -ErrorAction Stop

    } catch {

        if ($desired_value -eq "") {

            Output "NDF-OK|$($path)\$($key)|Desired: <EMPTY>|Set: Not Defined" Green

        }

        Output "NDF|$($path)\$($key)|Desired: $($desired_value)|Set: Not Defined" Red

        return

    }

 

    if ($desired_value -eq "") {

        Output "OK|$($path)\$($key)|Desired: <EMPTY>|Set: <EMPTY>" Red

        return

    }

   

 

    if ($entry -eq $desired_value) {

        Output "OK|$($path)\$($key)|Desired: $($desired_value)|Set: $($entry)" Green

    } else {

        Output "NOK|$($path)\$($key)|Desired: $($desired_value)|Set: $($entry)" Red

    }

}

 

function CheckIncludes([string] $role, [string[]] $values) {

    $includes = $false

    $is_set = $false

 

    for($i=0; $i -lt $current.Length; $i++) {

        if($current[$i].Contains($role)) {

            $includes = $true

            $is_set = $true

            for($j=0; $j -lt $values.Length; $j++) {

                if(-Not $current[$i].Contains($values[$j])) {

                    $includes=$false

                    break

                }

            }

        }

    }

 

    if(-Not $is_set) {

        Output "NDF|$($role)|Desired: $($values)|Set: Not Defined" Red

        return

    }

 

    if($includes) {

        Output "OK|$($role)|Desired: $($values)|Contains all required settings" Green

    } else {

        Output "NOK|$($role)|Desired: $($values)|Does not contain all required settings" Red

    }

}

 

# "SeTrustedCredManAccessPrivilege" ($SID_NOONE)

function GetSecurityPolicy([string] $role, [string[]] $values) {

    $desired = "$($role)="

    $role = $role.Replace(' ', '')

 

    $current = $current.Replace(' ', '')

 

    for($r =0; $r -lt $values.Length; $r++){

        if($r -eq $values.Length -1) {

            $desired = "$($desired)$($values[$r])"

        } else {

            $desired = "$($desired)$($values[$r]),"

        }

    }

    $desired = $desired.Replace(' ', '')

 

    for($i=0; $i -lt $current.Length; $i++) {

        if($current[$i].Contains($role)) {

            if($desired -eq $current[$i]) {

                Output "OK|$($role)|Desired: $($desired)|Set: $($current[$i])" Green

            } else {

                Output "NOK|$($role)|Desired: $($desired)|Set: $($current[$i])" Red

            }

            return

        }

    }

    if($values -eq ($SID_NOONE)) {

        Output "NDF-OK|$($role)|Desired: $($desired)|Set: Not Defined" Green

    } else {

        Output "NDF|$($role)|Desired: $($desired)|Set: Not Defined" Red

    }

}

 

function GetAuditPol([string] $key, [string] $desired) {

    for($r=0; $r -lt $auditpol.Length; $r++) {

        if($auditpol[$r].Contains($key)) {

            $value = $auditpol[$r].Split(",")[4]

            if($value -eq $desired){

                Output "OK|$($key)|Desired: $($desired)|Set: $($value)" Green

            } else {

                Output "NOK|$($key)|Desired: $($desired)|Set: $($value)" Red

            }

            return

        }

    }

 

    Output "NDF|$($key)|Desired: $($desired)|Set: Not Defined" Red

}

 

try {

    secedit /export /cfg secpol.cfg

    $current = Get-Content secpol.cfg

} catch {

    Output "ERR|Security policy export failed" Red

    Exit

}

Write-Host "Security policy export done" -ForegroundColor Green

 

try {

    auditpol /get /r /category:* > auditpol.txt

    $auditpol = Get-Content auditpol.txt

} catch {

    Output "ERR|Audit policy export failed" Red

    Exit

}

Write-Host "INFO|Audit policy export done" -ForegroundColor Green

 

Output "`nSECTION|Password and Lockout policy`n"

 

$net = $(net accounts).Replace(' ','').Replace(':','||')

for($r=1; $r -lt $net.Length-6; $r++) {

    $o = "MAN|" + $net[$r]

    Output $o

}

 

Output "MAN-UI|Password must meet complexity requirements|Enabled"

 

GetRegEntry "HKLM:\System\CurrentControlSet\Control\SAM" "RelaxMinimumPasswordLengthLimits" "1"

# This setting is only available within the built-in OS security template of Windows 10 Release 2004 and Server 2022 (or newer), and is not available via older versions of the OS, or via downloadable Administrative Templates (ADMX/ADML).

 

Output "MAN-UI|Password can be stored using reversible encryption|Disabled"

 

for($r=5; $r -lt $net.Length-3; $r++) {

    $o = "MAN|" + $net[$r]

    Output $o

}

 

Output "`nSECTION|Security policy`n"

 

GetSecurityPolicy "SeTrustedCredManAccessPrivilege" ($SID_NOONE)

GetSecurityPolicy "SeNetworkLogonRight" ($SID_AUTHENTICATED_USERS, $SID_ADMINISTRATORS)

GetSecurityPolicy "SeTcbPrivilege" ($SID_NOONE)

GetSecurityPolicy "SeIncreaseQuotaPrivilege" ($SID_LOCAL_SERVICE, $SID_NETWORK_SERVICE, $SID_ADMINISTRATORS)

GetSecurityPolicy "SeInteractiveLogonRight" ($SID_ADMINISTRATORS)

GetSecurityPolicy "SeRemoteInteractiveLogonRight" ($SID_ADMINISTRATORS, $SID_REMOTE_DESKTOP_USERS)

GetSecurityPolicy "SeBackupPrivilege" ($SID_ADMINISTRATORS)

GetSecurityPolicy "SeSystemtimePrivilege" ($SID_LOCAL_SERVICE,$SID_ADMINISTRATORS)

GetSecurityPolicy "SeTimeZonePrivilege" ($SID_LOCAL_SERVICE,$SID_ADMINISTRATORS)

GetSecurityPolicy "SeCreatePagefilePrivilege" ($SID_ADMINISTRATORS)

GetSecurityPolicy "SeCreateTokenPrivilege" ($SID_NOONE)

GetSecurityPolicy "SeCreateGlobalPrivilege" ($SID_LOCAL_SERVICE,$SID_NETWORK_SERVICE,$SID_ADMINISTRATORS,$SID_SERVICE)

GetSecurityPolicy "SeCreatePermanentPrivilege" ($SID_NOONE)

GetSecurityPolicy "SeCreateSymbolicLinkPrivilege" ($SID_ADMINISTRATORS,$SID_VIRTUAL_MACHINE)

GetSecurityPolicy "SeDebugPrivilege" ($SID_ADMINISTRATORS)

CheckIncludes "SeDenyNetworkLogonRight" ($SID_LOCAL_ACCOUNT,$SID_GUESTS) # should also include members of Administrators group

CheckIncludes "SeDenyBatchLogonRight" ($SID_GUESTS)

CheckIncludes "SeDenyServiceLogonRight" ($SID_GUESTS)

CheckIncludes "SeDenyInteractiveLogonRight" ($SID_GUESTS)

GetSecurityPolicy "SeDenyRemoteInteractiveLogonRight" ($SID_LOCAL_ACCOUNT,$SID_GUESTS)

GetSecurityPolicy "SeDelegateSessionUserImpersonatePrivilege" ($SID_NOONE)

GetSecurityPolicy "SeRemoteShutdownPrivilege" ($SID_ADMINISTRATORS)

GetSecurityPolicy "SeAuditPrivilege" ($SID_LOCAL_SERVICE,$SID_NETWORK_SERVICE)

GetSecurityPolicy "SeImpersonatePrivilege" ($SID_LOCAL_SERVICE,$SID_NETWORK_SERVICE,$SID_ADMINISTRATORS,$SID_SERVICE)

GetSecurityPolicy "SeIncreaseBasePriorityPrivilege" ($SID_ADMINISTRATORS,$SID_WINDOW_MANAGER_GROUP)

GetSecurityPolicy "SeLoadDriverPrivilege" ($SID_ADMINISTRATORS)

GetSecurityPolicy "SeLockMemoryPrivilege" ($SID_NOONE)

GetSecurityPolicy "SeSecurityPrivilege" ($SID_ADMINISTRATORS)

GetSecurityPolicy "SeRelabelPrivilege" ($SID_NOONE)

GetSecurityPolicy "SeSystemEnvironmentPrivilege" ($SID_ADMINISTRATORS)

GetSecurityPolicy "SeManageVolumePrivilege" ($SID_ADMINISTRATORS)

GetSecurityPolicy "SeProfileSingleProcessPrivilege" ($SID_ADMINISTRATORS)

GetSecurityPolicy "SeSystemProfilePrivilege" ($SID_ADMINISTRATORS,$SID_WDI_SYSTEM_SERVICE)

GetSecurityPolicy "SeAssignPrimaryTokenPrivilege" ($SID_LOCAL_SERVICE, $SID_NETWORK_SERVICE)

GetSecurityPolicy "SeRestorePrivilege" ($SID_ADMINISTRATORS)

GetSecurityPolicy "SeShutdownPrivilege" ($SID_ADMINISTRATORS)

GetSecurityPolicy "SeTakeOwnershipPrivilege" ($SID_ADMINISTRATORS)

 

GetSecurityPolicy "EnableAdminAccount" ("0")

GetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser" ("4,3")

GetSecurityPolicy "EnableGuestAccount" ("0")

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse" ("4,1")

Output "MAN-UI|Rename administrator account|Not 'Administrator'"

Output "MAN-UI|Rename guest account|Not 'Guest'"

# Rename guest account and administrator account needs to be checked manually

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy" ("4,1")

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail" ("4,0")

 

GetSecurityPolicy "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD" ("1,`"0`"")

Output "INFO|AllocateDASD|Not defined is also OK"

 

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers" ("4,1")

 

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal" ("4,1")

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel" ("4,1")

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel" ("4,1")

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange" ("4,0")

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge" ("4,30")

Output "INFO|MaximumPasswordAge|Lower than 30 is also OK"

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey" ("4,1")

 

GetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD" ("4,0")

GetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName" ("4,1")

GetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs" ("4,900")

Output "INFO|InactivityTimeoutSecs|Lower than 900 is also OK"

Output "MAN|Message text for users attempting to log on|Desired: <SOMETHING>|Set: $(Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeText")"

Output "MAN|Message title for users attempting to log on|Desired: <SOMETHING>|Set: $(Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeCaption")"

# Message for users needs to be checked manually

 

GetSecurityPolicy "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount" ("1,`"4`"")

Output "INFO|CachedLogonsCount|Lower than 4 is also OK"

GetSecurityPolicy "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning" ("4,14")

Output "INFO|PasswordExpiryWarning|Between 5 and 14 is OK"

GetSecurityPolicy "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon" ("4,1")

GetSecurityPolicy "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption" ("1,`"1`"")

Output "INFO|ScRemoveOption|Higher than 1 is also OK"

 

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature" ("4,1")

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature" ("4,1")

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword" ("4,0")

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect" ("4,15")

Output "INFO|AutoDisconnect|Lower than 15 is also OK"

 

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature" ("4,1")

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature" ("4,1")

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff" ("4,1")

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\SmbServerNameHardeningLevel" ("4,1")

Output "INFO|SmbServerNameHardeningLevel|Higher than 1 is also OK"

 

GetSecurityPolicy "LSAAnonymousNameLookup" ("0")

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM" ("4,1")

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous" ("4,1")

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds" ("4,1")

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous" ("4,0")

GetRegEntry "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "NullSessionPipes" ""

Output "MAN|Network access: Remotely accessible registry paths|Desired: System\CurrentControlSet\Control\ProductOptions System\CurrentControlSet\Control\Server Applications Software\Microsoft\Windows NT\CurrentVersion|Set: $(Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths" -Name "Machine")"

Output "MAN|Network access: Remotely accessible registry paths and sub-paths|Desired: System\CurrentControlSet\Control\Print\Printers System\CurrentControlSet\Services\Eventlog Software\Microsoft\OLAP Server Software\Microsoft\Windows NT\CurrentVersion\Print Software\Microsoft\Windows NT\CurrentVersion\Windows System\CurrentControlSet\Control\ContentIndex System\CurrentControlSet\Control\Terminal Server System\CurrentControlSet\Control\Terminal Server\UserConfig System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration Software\Microsoft\Windows NT\CurrentVersion\Perflib System\CurrentControlSet\Services\SysmonLog|Set: $(Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths" -Name "Machine")"

 

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess" ("4,1")

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictRemoteSAM" ("1,`"O:BAG:BAD:(A;;RC;;;BA)`"")

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares" ("7,")

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest" ("4,0")

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId" ("4,1")

 

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback " ("4,0")

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\pku2u\AllowOnlineID " ("4,0")

GetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes" ("4,2147483640")

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash" ("4,1")

GetSecurityPolicy "ForceLogoffWhenHourExpire" ("1")

 

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel" ("4,5")

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity" ("4,1")

Output "INFO|LDAPClientIntegrity|Higher than 1 is also OK"

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec" ("4,537395200")

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec" ("4,537395200")

GetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon" ("4,0")

 

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive" ("4,1")

GetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode" ("4,1")

GetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken" ("4,1")

GetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin" ("4,2")

GetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser" ("4,0")

 

GetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection" ("4,1")

GetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths" ("4,1")

GetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA" ("4,1")

GetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop" ("4,1")

GetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization" ("4,1")

 

GetRegEntry "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler" "Start" "4"

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "EnableFirewall" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "DefaultInboundAction" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "DefaultOutboundAction" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "DisableNotifications" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogFilePath" "%SystemRoot%\System32\logfiles\firewall\domainfw.log"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogFileSize" "16384"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogDroppedPackets" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogSuccessfulConnections" "1"

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "EnableFirewall" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "DefaultInboundAction" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "DefaultOutboundAction" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "DisableNotifications" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogFilePath" "%SystemRoot%\System32\logfiles\firewall\privatefw.log"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogFileSize" "16384"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogDroppedPackets" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogSuccessfulConnections" "1"

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "EnableFirewall" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "DefaultInboundAction" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "DefaultOutboundAction" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "DisableNotifications" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "PublicAllowLocalPolicyMerge" "0" # cannot check this rule

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" "PublicAllowLocalIPsecPolicyMerge" "0" # cannot check this rule

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogFilePath" "%SystemRoot%\System32\logfiles\firewall\publicfw.log"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogFileSize" "16384"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogDroppedPackets" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogSuccessfulConnections" "1"

 

Output "`nSECTION|Audit policy`n"

 

GetAuditPol "Credential Validation" "Success and Failure"

GetAuditPol "Application Group Management" "Success and Failure"

GetAuditPol "Security Group Management" "Success"

GetAuditPol "User Account Management" "Success and Failure"

GetAuditPol "Plug and Play Events" "Success"

GetAuditPol "Process Creation" "Success"

GetAuditPol "Account Lockout" "Failure"

GetAuditPol "Group Membership" "Success"

GetAuditPol "Logoff" "Success"

GetAuditPol "Logon" "Success and Failure"

GetAuditPol "Other Logon/Logoff Events"  "Success and Failure"

GetAuditPol "Special Logon" "Success"

GetAuditPol "Detailed File Share" "Failure"

GetAuditPol "File Share" "Success and Failure"

GetAuditPol "Other Object Access Events" "Success and Failure"

GetAuditPol "Removable Storage" "Success and Failure"

GetAuditPol "Audit Policy Change" "Success"

GetAuditPol "Authentication Policy Change" "Success"

GetAuditPol "Authorization Policy Change" "Success"

GetAuditPol "MPSSVC Rule-Level Policy Change" "Success and Failure"

GetAuditPol "Other Policy Change Events" "Failure"

GetAuditPol "Sensitive Privilege Use" "Success and Failure"

GetAuditPol "IPsec Driver" "Success and Failure"

GetAuditPol "Other System Events" "Success and Failure"

GetAuditPol "Security State Change" "Success"

GetAuditPol "Security System Extension" "Success"

GetAuditPol "System Integrity" "Success and Failure"

 

# ADMINISTRATIVE TEMPLATES START HERE

Output "`nSECTION|Administrative templates (Computer)`n"

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenCamera" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenSlideshow" "1"

# This Group Policy path may not exist by default. It is provided by the Group Policy template

# ControlPanelDisplay.admx/adml that is included with the Microsoft Windows 8.1 &

# Server 2012 R2 Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" "AllowInputPersonalization" "0"

# This Group Policy section is provided by the Group Policy template Globalization.admx/adml that is

# included with the Microsoft Windows 8.0 & Server 2012 (non-R2) Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "AllowOnlineTips" "0"

 

# GetRegEntry "HKLM:\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}" "DllName" "C:\Program Files\LAPS\CSE\AdmPwd.dll"

GetRegEntry "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}" "DllName" "C:\Program Files\LAPS\CSE\AdmPwd.dll"

Output "INFO|DllName|Other location is also OK as long as LAPS is present"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" "PwdExpirationProtectionEnabled" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" "AdmPwdEnabled" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" "PasswordComplexity" "4"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" "PasswordLength" "15"

Output "INFO|PasswordLength|More than 15 is also OK"

GetRegEntry "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd" "PasswordAgeDays" "30"

Output "INFO|PasswordAgeDays|Lower than 30 is also OK"

# This Group Policy section is provided by the Group Policy template AdmPwd.admx/adml that is included with LAPS.

 

GetRegEntry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LocalAccountTokenFilterPolicy" "0"

GetRegEntry "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb1" "Start" "1"

GetRegEntry "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1" "0"

GetRegEntry "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "DisableExceptionChainValidation" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" "RestrictDriverInstallationToAdministrators" "1"

GetRegEntry "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" "NodeType" "2"

GetRegEntry "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential" "0"

# This Group Policy section is provided by the Group Policy template SecGuide.admx/adml

 

GetRegEntry "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon" "0"

GetRegEntry "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisableIPSourceRouting" "2"

GetRegEntry "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "DisableIPSourceRouting" "2"

GetRegEntry "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "EnableICMPRedirect" "0"

GetRegEntry "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "KeepAliveTime" "300000"

GetRegEntry "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" "NoNameReleaseOnDemand" "1"

GetRegEntry "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "PerformRouterDiscovery" "0"

GetRegEntry "HKLM:\SYSTEM\CurrentControlSet\Control\SessionManager" "SafeDllSearchMode" "1"

GetRegEntry "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "ScreenSaverGracePeriod" "5"

Output "INFO|ScreenSaverGracePeriod|Lower than 5 is also OK"

GetRegEntry "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" "TcpMaxDataRetransmissions" "3"

GetRegEntry "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "TcpMaxDataRetransmissions" "3"

GetRegEntry "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security" "WarningLevel" "90"

Output "INFO|WarningLevel|Lower than 90 is also OK"

# This Group Policy section is provided by the Group Policy template MSS-legacy.admx/adml that is available

# from this TechNet blog post: The MSS settings – Microsoft Security Guidance blog

 

GetRegEntry "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "DoHPolicy" "1"

Output "INFO|DoHPolicy|Lower than 1 is also OK"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" "0"

# This Group Policy section is provided by the Group Policy template DnsClient.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableFontProviders" "0"

# This Group Policy section is provided by the Group Policy template GroupPolicy.admx/adml that is

# included with the Microsoft Windows 10 Release 1607 & Server 2016 Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" "AllowInsecureGuestAuth" "0"

# This Group Policy section is provided by the Group Policy template LanmanWorkstation.admx/adml that is

# included with the Microsoft Windows 10 RTM (Release 1507) Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "AllowLLTDIOOnDomain" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "AllowLLTDIOOnPublicNet" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "EnableLLTDIO" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "ProhibitLLTDIOOnPrivateNet" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "AllowRspndrOnDomain" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "AllowRspndrOnPublicNet" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "EnableRspndr" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "ProhibitRspndrOnPrivateNet" "0"

# This Group Policy section is provided by the Group Policy template LinkLayerTopologyDiscovery.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" "Disabled" "1"

# This Group Policy section is provided by the Group Policy template P2P-pnrp.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" "NC_AllowNetBridge_NLA" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" "NC_ShowSharedAccessUI" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" "NC_StdDomainUserSetLocation" "1"

# This Group Policy path is provided by the Group Policy template NetworkConnections.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" [file://*/NETLOGON]\\*\NETLOGON "RequireMutualAuthentication=1, RequireIntegrity=1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" [file://*/SYSVOL]\\*\SYSVOL "RequireMutualAuthentication=1, RequireIntegrity=1"

# This Group Policy path does not exist by default. An additional Group Policy template (NetworkProvider.admx/adml)

# is required - it is included with the MS15-011 / MSKB 3000483 security update or with the Microsoft

# Windows 10 RTM (Release 1507) Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" "DisabledComponents" "255"

# This Group Policy section is provided by the Group Policy template tcpip.admx/adml that is

# included with the Microsoft Windows 7 & Server 2008 R2 Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" "EnableRegistrars" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" "DisableUPnPRegistrar" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" "DisableInBand802DOT11Registrar" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" "DisableFlashConfigRegistrar" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" "DisableWPDRegistrar" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" "DisableWcnUi" "1"

# This Group Policy section is provided by the Group Policy template WindowsConnectNow.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" "fMinimizeConnections" "3"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" "fBlockNonDomain" "1"

# This Group Policy section is provided by the Group Policy template WCM.admx/adml that is

# included with the Microsoft Windows 8.0 & Server 2012 (non-R2) Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "RegisterSpoolerRemoteRpcEndPoint" "2"

GetRegEntry "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" "NoWarningNoElevationOnInstall" "0"

GetRegEntry "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" "UpdatePromptSettings" "0"

# This Group Policy section is provided by the Group Policy template Printing.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoCloudApplicationNotification" "1"

# This Group Policy section is provided by the Group Policy template WPN.admx/adml that is

# included with the Microsoft 10 Release 1803 Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled" "1"

# This Group Policy section is provided by the Group Policy template AuditSettings.admx/adml that is

# included with the Microsoft Windows 8.1 & Server 2012 R2 Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" "AllowEncryptionOracle" "0"

# s Group Policy section is provided by the Group Policy template CredSsp.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" "AllowProtectedCreds" "1"

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "EnableVirtualizationBasedSecurity" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "RequirePlatformSecurityFeatures" "3"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "HypervisorEnforcedCodeIntegrity" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "HVCIMATRequired" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "LsaCfgFlags" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "ConfigureSystemGuardLaunch" "1"

# This Group Policy section is provided by the Group Policy template DeviceGuard.admx/adml that is

# included with the Microsoft Windows 10 RTM (Release 1507) Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" "PreventDeviceMetadataFromNetwork" "1"

 

GetRegEntry "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" "DriverLoadPolicy" "3"

# This Group Policy section is provided by the Group Policy template EarlyLaunchAM.admx/adml that is

# included with the Microsoft Windows 8.0 & Server 2012 (non-R2) Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" "NoBackgroundPolicy" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" "NoGPOListChanges" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableCdp" "0"

GetRegEntry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableBkGndGroupPolicy" "0"

# This Group Policy path may not exist by default. It is provided by the Group Policy template GroupPolicy.admx/adml that is

# included with the Microsoft Windows 8.0 & Server 2012 (non-R2) Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "DisableWebPnPDownload" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" "PreventHandwritingDataSharing" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" "PreventHandwritingErrorReports" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" "ExitOnMSICW" "1"

GetRegEntry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoWebServices" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "DisableHTTPPrinting" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" "NoRegistration" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion" "DisableContentFileUpdates" "1"

GetRegEntry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoOnlinePrintsWizard" "1"

GetRegEntry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoPublishingWizard" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" "CEIP" "2"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" "CEIPEnable" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" "Disabled" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" "DoReport" "1"

# This Group Policy section is provided by the Group Policy template Windows.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters" "DevicePKInitBehavior" "1"

GetRegEntry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters" "DevicePKInitEnabled" "1"

# This Group Policy section is provided by the Group Policy template Kerberos.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" "DeviceEnumerationPolicy" "1"

# This Group Policy section is provided by the Group Policy template DmaGuard.admx/adml that is included

# with the Microsoft Windows 10 Release 1809 and Server 2019 Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" "BlockUserInputMethodsForSignIn" "1"

# This Group Policy section is provided by the Group Policy template Globalization.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "BlockUserFromShowingAccountDetailsOnSignin" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DontDisplayNetworkSelectionUI" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DontEnumerateConnectedUsers" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnumerateLocalUsers" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DisableLockScreenAppNotifications" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "BlockDomainPicturePassword" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "AllowDomainPINLogon" "0"

# This Group Policy section is provided by the Group Policy template Logon.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "AllowCrossDeviceClipboard" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "UploadUserActivities" "0"

# This Group Policy section is provided by the Group Policy template OSPolicy.admx/adml that is

# included with the Microsoft Windows 10 Release 1709 Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e898b7-4186-b944-eafa664402d9" "DCSettingIndex" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e898b7-4186-b944-eafa664402d9" "ACSettingIndex" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb100d-47d6-a2d5-f7d2daa51f51" "DCSettingIndex" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb100d-47d6-a2d5-f7d2daa51f51" "ACSettingIndex" "1"

# This Group Policy section is provided by the Group Policy template Power.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowUnsolicited" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowToGetHelp" "0"

# This Group Policy section is provided by the Group Policy template RemoteAssistance.admx/adml that is included

# with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" "EnableAuthEpResolution" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" "RestrictRemoteClients" "1"

# GetRegEntry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM" "SamNGCKeyROCAValidation" "1"

# Output "INFO|Higher than 1 is also OK"

# This Group Policy section is provided by the Group Policy template RPC.admx/adml that is included

# with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" "DisableQueryRemoteServer" "0"

# This Group Policy section is provided by the Group Policy template MSDT.admx/adml that is included

# with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b9654fc3-8781-88dd50a6299d}" "ScenarioExecutionEnabled" "0"

# This Group Policy section is provided by the Group Policy template PerformancePerftrack.admx/adml that is

# included with the Microsoft Windows 7 & Server 2008 R2 Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" "DisabledByGroupPolicy" "1"

# This Group Policy section is provided by the Group Policy template UserProfiles.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" "Enabled" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer" "Enabled" "0"

# This Group Policy section is provided by the Group Policy template W32Time.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" "AllowSharedLocalAppData" "0"

# This Group Policy section is provided by the Group Policy template AppxPackageManager.admx/adml that is

# included with the Microsoft Windows 8.0 & Server 2012 (non-R2) Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "MSAOptional" "1"

# This Group Policy section is provided by the Group Policy template AppXRuntime.admx/adml that is

#  included with the Microsoft Windows 8.0 & Server 2012 (non-R2) Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoAutoplayfornonVolume" "1"

GetRegEntry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun" "1"

GetRegEntry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun" "1"

# This Group Policy section is provided by the Group Policy template AutoPlay.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" "EnhancedAntiSpoofing" "1"

# This Group Policy section is provided by the Group Policy template Biometrics.admx/adml that is

# included with the Microsoft Windows 10 Release 1511 Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Camera" "AllowCamera" "0"

# This Group Policy section is provided by the Group Policy template Camera.admx/adml that is

# included with the Microsoft Windows 10 Release 1607 & Server 2016 Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableConsumerAccountStateContent" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" "RequirePinForPairing" "1"

# This Group Policy section is provided by the Group Policy template CloudContent.admx/adml that is

# included with the Microsoft Windows 10 Release 1511 Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" "DisablePasswordReveal" "1"

# This Group Policy section is provided by the Group Policy template WirelessDisplay.admx/adml that is

# included with the Microsoft Windows 10 Release 1607 & Server 2016 Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" "EnumerateAdministrators" "0"

# This Group Policy path is provided by the Group Policy template CredUI.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DisableEnterpriseAuthProxy" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DisableOneSettingsDownloads" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DoNotShowFeedbackNotifications" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "EnableOneSettingsAuditing" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "LimitDiagnosticLogCollection" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "LimitDumpCollection" "1"

# This Group Policy path is provided by the Group Policy template DataCollection.admx/adml that is

# included with the Microsoft Windows 10 RTM (Release 1507) Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" "AllowBuildPreview" "0"

# This Group Policy is provided by the Group Policy template AllowBuildPreview.admx/adml that is

# included with the Microsoft Windows 10 RTM (Release 1507) Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" "Retention" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" "MaxSize" "32768"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" "Retention" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" "MaxSize" "196608"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" "Retention" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" "MaxSize" "32768"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" "Retention" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" "MaxSize" "32768"

# This Group Policy section is provided by the Group Policy template EventLog.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoDataExecutionPrevention" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoHeapTerminationOnCorruption" "0"

GetRegEntry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "PreXPSP2ShellProtocolBehavior" "0"

# This Group Policy path may not exist by default. It is provided by the Group Policy template Explorer.admx/adml that is

# included with the Microsoft Windows 7 & Server 2008 R2 Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocation" "1"

# This Group Policy section is provided by the Group Policy template Sensors.admx/adml that is included

# with the Microsoft Windows 7 & Server 2008 R2 Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" "AllowMessageSync" "0"

# This Group Policy section is provided by the Group Policy template Messaging.admx/adml that is

# included with the Microsoft Windows 10 Release 1709 Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" "DisableUserAuth" "1"

# This Group Policy path may not exist by default. It is provided by the Group Policy template MSAPolicy.admx/adml that is

# included with the Microsoft Windows 10 Release 1703 Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" "LocalSettingOverrideSpynetReporting" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" "SpynetReporting" "0"

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" "ExploitGuard_ASR_Rules" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "26190899-1602-49e8-8b27-eb1d0a1ce869" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "3b576869-a4ec-4529-8536-b80a7769e899" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "5beb7efe-fd9a-4556-801d-275e5ffc04cc" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "d3e037e1-3eb8-44c8-a917-57927947596d" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "d4f940ab-401b-4efc-aadc-ad5f3c50688a" "1"

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" "EnableNetworkProtection" "1"

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" "EnableFileHashComputation" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableIOAVProtection" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableRealtimeMonitoring" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableBehaviorMonitoring" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableScriptScanning" "0"

 

GetRegEntry "HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" "DisableGenericRePorts" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" "DisableRemovableDriveScanning" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" "DisableEmailScanning" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" "PUAProtection" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" "DisableAntiSpyware" "0"

# This Group Policy section is provided by the Group Policy template WindowsDefender.admx/adml that is

# included with the Microsoft Windows 8.1 & Server 2012 R2 Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" "1"

# The Group Policy settings contained within this section are provided by the Group Policy template SkyDrive.admx/adml that is

# included with the Microsoft Windows 8.1 & Server 2012 R2 Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\PushToInstall" "DisablePushToInstall" "1"

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "DisablePasswordSaving" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "f" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Service" "fDisableCcm" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisableCdm" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Service" "fDisableLPT" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisablePNPRedir" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fPromptForPassword" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fEncryptRPCTraffic" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "SecurityLayer" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "UserAuthentication" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MinEncryptionLevel" "3"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MaxIdleTime" "15"

Output "INFO|MaxIdleTime|Lower than 15 is also OK"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MaxDisconnectionTime" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "DeleteTempDirsOnExit" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "PerSessionTempDir" "0"

# This Group Policy section is provided by the Group Policy template TerminalServer.admx/adml that is included

# with the Microsoft Windows 8.0 & Server 2012 (non-R2) Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" "DisableEnclosureDownload" "1"

# This Group Policy section is provided by the Group Policy template InetRes.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCloudSearch" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowIndexingEncryptedStoresOrItems" "0"

# This Group Policy path may not exist by default. It is provided by the Group Policy template Search.admx/adml that is

# included with the Microsoft Windows 10 Release 1709 Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" "NoGenTicket" "1"

# This Group Policy section is provided by the Group Policy template AVSValidationGP.admx/adml that is included

# with the Microsoft Windows 10 RTM (Release 1507) Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "ShellSmartScreenLevel" "0"

# The Group Policy settings contained within this section are provided by the Group Policy template WindowsExplorer.admx/adml that is

# included with the Microsoft Windows 10 Release 1703 Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" "AllowSuggestedAppsInWindowsInkWorkspace" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" "AllowWindowsInkWorkspace" "1"

# This Group Policy section is provided by the Group Policy template WindowsInkWorkspace.admx/adml that is

# included with the Microsoft Windows 10 Release 1607 & Server 2016 Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "EnableUserControl" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "SafeForScripting" "0"

# This Group Policy section is provided by the Group Policy template MSI.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableAutomaticRestartSignOn" "1"

# This Group Policy section is provided by the Group Policy template WinLogon.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging" "1"

# This Group Policy section is provided by the Group Policy template PowerShellExecutionPolicy.admx/adml that is

# included with the Microsoft Windows 8.0 & Server 2012 (non-R2) Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting" "0"

# This Group Policy section is provided by the Group Policy template WindowsRemoteManagement.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowBasic" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowUnencryptedTraffic" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowDigest" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowBasic" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowAutoConfig" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowUnencryptedTraffic" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "DisableRunAs" "1"

# This Group Policy section is provided by the Group Policy template WindowsRemoteManagement.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" "AllowRemoteShellAccess" "0"

# This Group Policy section is provided by the Group Policy template WindowsRemoteShell.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" "DisallowExploitProtectionOverride" "1"

# This Group Policy section is provided by the Group Policy template WindowsDefenderSecurityCenter.admx/adml that is

# included with the Microsoft Windows 10 Release 1709 Administrative Templates (or newer).

 

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoRebootWithLoggedOnUsers" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallDay" "0"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "ManagePreviewBuilds" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "ManagePreviewBuildsPolicyValue" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferFeatureUpdates" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferFeatureUpdatesPeriodInDays" "180"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "BranchReadinessLevel" "16"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferQualityUpdates" "1"

GetRegEntry "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferQualityUpdatesPeriodInDays" "0"

# This Group Policy section is provided by the Group Policy template WindowsUpdate.admx/adml that is

# included with the Microsoft Windows 11 Release 21H2 Administrative Templates (or newer).

 

$sid = $(whoami /user)[6].Split(' ')[1]

 

GetRegEntry "Registry::HKEY_USERS\$($sid)\Software\Policies\Microsoft\Windows\Control Panel\Desktop" "ScreenSaveActive" "1"

GetRegEntry "Registry::HKEY_USERS\$($sid)\Software\Policies\Microsoft\Windows\Control Panel\Desktop" "ScreenSaverIsSecure" "1"

GetRegEntry "Registry::HKEY_USERS\$($sid)\Software\Policies\Microsoft\Windows\Control Panel\Desktop" "ScreenSaveTimeOut" "900"

Output "INFO|ScreenSaveTimeOut|Lower than 900 (but not 0) is also OK"

# This Group Policy path may not exist by default. It is provided by the Group Policy template ControlPanelDisplay.admx/adml that is

# included with the Microsoft Windows 7 & Server 2008 R2 Administrative Templates (or newer).

 

GetRegEntry "Registry::HKEY_USERS\$($sid)\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoToastApplicationNotificationOnLockScreen" "1"

# This Group Policy path may not exist by default. It is provided by the Group Policy template WPN.admx/adml that is

# included with the Microsoft Windows 8.0 & Server 2012 (non-R2) Administrative Templates (or newer).

 

GetRegEntry "Registry::HKEY_USERS\$($sid)\Software\Policies\Microsoft\Assistance\Client\1.0" "NoImplicitFeedback" "1"

# This Group Policy path is provided by the Group Policy template HelpAndSupport.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "Registry::HKEY_USERS\$($sid)\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" "SaveZoneInformation" "2"

GetRegEntry "Registry::HKEY_USERS\$($sid)\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" "ScanWithAntiVirus" "3"

# This Group Policy path is provided by the Group Policy template AttachmentManager.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "Registry::HKEY_USERS\$($sid)\Software\Policies\Microsoft\Windows\CloudContent" "ConfigureWindowsSpotlight" "2"

GetRegEntry "Registry::HKEY_USERS\$($sid)\Software\Policies\Microsoft\Windows\CloudContent" "DisableThirdPartySuggestions" "1"

GetRegEntry "Registry::HKEY_USERS\$($sid)\Software\Policies\Microsoft\Windows\CloudContent" "DisableTailoredExperiencesWithDiagnosticData" "1"

GetRegEntry "Registry::HKEY_USERS\$($sid)\Software\Policies\Microsoft\Windows\CloudContent" "DisableWindowsSpotlightFeatures" "1"

GetRegEntry "Registry::HKEY_USERS\$($sid)\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableSpotlightCollectionOnDesktop" "1"

# This Group Policy path may not exist by default. It is provided by the Group Policy template CloudContent.admx/adml that is

# included with the Microsoft Windows 10 Release 1607 & Server 2016 Administrative Templates (or newer).

 

GetRegEntry "Registry::HKEY_USERS\$($sid)\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoInplaceSharing" "1"

# This Group Policy path is provided by the Group Policy template Sharing.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "Registry::HKEY_USERS\$($sid)\Software\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated" "0"

# This Group Policy path is provided by the Group Policy template MSI.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

GetRegEntry "Registry::HKEY_USERS\$($sid)\Software\Policies\Microsoft\WindowsMediaPlayer" "PreventCodecDownload" "1"

# This Group Policy path is provided by the Group Policy template WindowsMediaPlayer.admx/adml that is

# included with all versions of the Microsoft Windows Administrative Templates.

 

Write-Host "`nDone`nRemoving export files..."

 

try {

    Remove-Item .\auditpol.txt

} catch {

    Write-Host "Failed to remove auditpol.txt" -ForegroundColor Red

}

 

try {

    Remove-Item .\secpol.cfg

} catch {

    Write-Host "Failed to remove secpol.cfg" -ForegroundColor Red

}