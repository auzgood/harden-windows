param(
[Parameter(Mandatory=$false,
           ValueFromPipelineByPropertyName=$true,
           Position=0)]
[Alias("ScriptsPath")]
[string]$TempDirectory,

[Parameter(Mandatory=$false,
           ValueFromPipelineByPropertyName=$true)]
[Alias("LogFileName")]
[string]$LogName,

[Parameter(Mandatory=$false)]
[switch]$Logging,

[Parameter(Mandatory=$false)]
[switch]$ScriptCleanup
)

#region Functions Section: For Script-wide custom, or non-microsoft native, functions

#region Set Logging File if -Logging switch is enabled.
If (
     #If Logging Switch is set via command line,
     $Logging
    ){
      IF(
          #If $LogName variable is set, and is not full path to file.
          ![string]::IsNullOrEmpty($LogName) -and
          !($LogName -match ':')
         ){ 
            #Default to $Env:TEMP directory + Log file Name
            $ScriptLog = $env:TEMP + "\" + $LogName
            Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
            Write-Host -Object "INFO"  -BackgroundColor White -ForegroundColor Black -NoNewline
            Write-Host -Object  ": Logging file set to $ScriptLog"
           }
      Elseif ( 
                #If $LogName variable is set, and contains full path, and the parent folder exists.
                ![string]::IsNullOrEmpty($LogName) -and
                ($LogName -match (':')) -and
                (Test-Path -path ($LogName | Split-Path -Parent))
              ){
                #Set $ScriptLog to the specified $LogName full path value.
                $ScriptLog = $LogName
                Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
                Write-Host -Object "INFO"  -BackgroundColor White -ForegroundColor Black -NoNewline
                Write-Host -Object  ": Logging file set to $ScriptLog"
                }
      Elseif ( 
                #If $LogName variable is set, and contains full path, and the parent folder does not exist exists.
                ![string]::IsNullOrEmpty($LogName) -and
                ($LogName -match (':')) -and
                !(Test-Path -path ($LogName | Split-Path -Parent))
              ){
                #Set $ScriptLog to the specified $Env:TEMP + $LogName.
                $ScriptLog = ($env:TEMP + "\" + ($LogName | Split-Path -Leaf))
                Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
                Write-Host -Object "INFO"  -BackgroundColor White -ForegroundColor Black -NoNewline
                Write-Host -Object  ": Logging file set to $ScriptLog"
                }
      Elseif ( #If $LogName is not specified and $LogName is empty.
               [string]::IsNullOrEmpty($LogName)
              ){ 
                #Set $ScriptLog Default Path of $Env:Temp + Date + ScriptLog.txt (Ex: "C:\Temp\2015-06-02_ScriptLog.txt")
                $ScriptLog = $env:TEMP + "\" + (Get-date -Format yyyy-MM-dd)+ '_'+ 'ScriptLog.txt'
                Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
                Write-Host -Object "INFO"  -BackgroundColor White -ForegroundColor Black -NoNewline
                Write-Host -Object  ": Logging file set to $ScriptLog"
                }
      }
else {
       Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
       Write-Host -Object "   INFO"  -BackgroundColor White -ForegroundColor Black -NoNewline
       Write-Host -Object  ": Logging parameter switch not detected. Proceeding with logging to file as disabled."
      }
#endregion Set Logging File if -Logging switch is enabled

#region $TempDirectory Assignment
if ($host.name -eq 'ConsoleHost') {
    if ([string]::IsNullOrEmpty($TempDirectory)) {
        $TempDirectory = $MyInvocation.MyCommand.Path | split-path -Parent
    }
}
else {
    if ([string]::IsNullOrEmpty($TempDirectory) -and ($host.name -match 'ISE')) {
        #region Open Folder Dialog to select $TempDirectory Parameter if not specified.
        Function Select-FolderDialog {
            param([string]$Description="Select Folder",[string]$RootFolder="Desktop")
            [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null     
            $objForm = New-Object -TypeName System.Windows.Forms.FolderBrowserDialog
            $objForm.Rootfolder = $RootFolder
            $objForm.Description = $Description
            $Show = $objForm.ShowDialog()
            if ($Show -eq "OK") {
                Return $objForm.SelectedPath
            }
            else {
                Write-Error -Message "Operation cancelled by user."
            }
        }
        $TempDirectory = Select-FolderDialog
        #endregion Open Folder Dialog to select $TempDirectory Parameter if not specified.
    }
}
#endregion $TempDirectory Assignment

#region Banner
$bannerpath = "C:\ScriptLogs" + "\" + 'Secure Reg Script Log.txt'
Write-Output -InputObject "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") *****************************************************************" | Add-Content -Path $bannerpath
Write-Output -InputObject "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") *                    Update-Registries Logs                     *" | Add-Content -Path $bannerpath
Write-Output -InputObject "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") *****************************************************************" | Add-Content -Path $bannerpath
#endregion

#region Write-log function
Function Write-Log {
    Param (
    # The string to be written to the log.
    [Parameter( Mandatory=$true,
                ValueFromPipelineByPropertyName=$true,
                Position=0)]
    [ValidateNotNullOrEmpty()]
    [Alias("LogContent")]
    [string]$Message,

    # The path to the log file.
    [Parameter( Mandatory=$false,
                ValueFromPipelineByPropertyName=$true)]
    [Alias('LogPath')]
    [string]$Path= $ScriptLog,

    [Parameter( Mandatory=$false,
                ValueFromPipelineByPropertyName=$true,
                Position=3)]
    [ValidateSet("Error","Warn","Info","Success")]
    [string]$Level="Info"
    )
    if ($Logging) {
        switch ($Level) {
            'Error' {
                #Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") ERROR: $Message"
                Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
                Write-Host -Object "  ERROR"  -BackgroundColor Red -ForegroundColor Black -NoNewline
                Write-Host -Object  ": $Message"
                Write-Output -InputObject "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")   ERROR: $Message" | Add-Content -Path $Path
            }
            'Warn' {
                #Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") WARNING: $Message"
                Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
                Write-Host -Object "WARNING"  -BackgroundColor Yellow -ForegroundColor Black -NoNewline
                Write-Host -Object  ": $Message"
                Write-Output -InputObject "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") WARNING: $Message" | Add-Content -Path $Path
            }
            'Info' {
                Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
                Write-Host -Object "   INFO"  -BackgroundColor White -ForegroundColor Black -NoNewline
                Write-Host -Object  ": $Message"
                Write-Output -InputObject "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")    INFO: $Message" | Add-Content -Path $Path
            }
            'Success'{
                Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
                Write-Host -Object "SUCCESS"  -BackgroundColor DarkGreen -ForegroundColor White -NoNewline
                Write-Host -Object  ": $Message"
                Write-Output -InputObject "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") SUCCESS: $Message" | Add-Content -Path $Path
            }
        }
    }
    else {
        switch ($Level) {
            'Error' {
                Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
                Write-Host -Object "  ERROR"  -BackgroundColor Red -ForegroundColor Black -NoNewline
                Write-Host -Object  ": $Message"
            }
            'Warn' {
                Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
                Write-Host -Object "WARNING"  -BackgroundColor Yellow -ForegroundColor Black -NoNewline
                Write-Host -Object  ": $Message"
            }
            'Info' {
                Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
                Write-Host -Object "   INFO"  -BackgroundColor White -ForegroundColor Black -NoNewline
                Write-Host -Object  ": $Message"
            }
            'Success' {
                Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
                Write-Host -Object "SUCCESS"  -BackgroundColor DarkGreen -ForegroundColor White -NoNewline
                Write-Host -Object  ": $Message"
            }
        }
    }
}
#endregion Write-log Function

#region ScriptCleanup
if ($ScriptCleanup) {
    Write-Host -Object "ScriptCleanup switch paramenter specified. Script will delete itself."
    $CurrentScriptFullPathName = $MyInvocation.MyCommand.Definition
    $CurrentScriptName = $MyInvocation.MyCommand.Name
    Remove-Item -Path $CurrentScriptFullPathName
}
else {
    Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
    Write-Host -Object "INFO"  -BackgroundColor White -ForegroundColor Black -NoNewline
    Write-Host -Object  ": '-ScriptCleanup' switch paramenter NOT detected. Script will NOT delete itself."
}
#endregion Script Self Delete

if (![string]::IsNullOrEmpty($TempDirectory)) {
    Write-Log -Message "The TempDirectory parameter has been set to ""$TempDirectory""." -Level Info
}

Function Set-UserReg {
    [CmdletBinding()]
    Param(
            [ValidateScript({Test-Path -Path "$env:HOMEDRIVE\Users\$_"})]
            [Parameter( Position=1,
                        Mandatory=$true
                        )]$UserAccount,
            [Parameter( Position=2,
                        Mandatory=$true
                        )]$KeyPath,
            [Parameter( Position=3,
                        Mandatory=$true
                        )]$PropertyName,
            [Parameter( Position=4,
                        Mandatory=$true
                        )]$PropertyType,
            [Parameter( Position=5,
                        Mandatory=$true
                        )]$Value
          )
    Begin {
        $User = New-Object System.Security.Principal.NTAccount("$UserAccount")
        $SID = $User.Translate([System.Security.Principal.SecurityIdentifier]).value
        New-PSDrive HKU Registry HKEY_USERS | Out-Null

        if ((Get-ChildItem -Path "HKU:\" | select -ExpandProperty Name) -contains "HKEY_USERS\$SID") {
            $Loaded = $true
        }
        else {
            $Loaded = $false
        }
        Write-Verbose "$SID"
    }
    Process {
        if ($Loaded) {
            if (Test-Path -Path "HKU:\$SID\$KeyPath") {
                if ([String]::IsNullOrEmpty((Get-ItemProperty -Path "HKU:\$SID\$KeyPath" -ErrorAction silentlycontinue).$PropertyName)) {
                    Write-Verbose "Creating new property..."
                    New-ItemProperty -Path "HKU:\$SID\$KeyPath" -Name $PropertyName -PropertyType $PropertyType -Value $Value -Force | Out-Null
                }
                else {
                    Write-Verbose "Setting new property value..."
                    Set-ItemProperty -Path "HKU:\$SID\$KeyPath" -Name $PropertyName -Value $Value -Force | Out-Null
                }
                if ((Get-ItemProperty -Path "HKU:\$SID\$KeyPath" -ErrorAction silentlycontinue).$PropertyName -eq $Value) {
                    Write-Verbose "Successfully set new property value..."
                    Write-Verbose "Already loaded Test: True"
                    $Result = $true
                }
                else {
                    Write-Verbose "Already loaded Test: False" ; $Result = $false
                }
            }
            else {
                Write-Verbose "Creating Path ""\$KeyPath""  for ""$UserAccount"""
                New-Item -Path ("HKU:\$SID\$KeyPath" | Split-Path -Parent) -Name ("$KeyPath" | Split-Path -Leaf) -ItemType Directory -Force | Out-Null
                Write-Verbose "Creating new property..."
                New-ItemProperty -Path "HKU:\$SID\$KeyPath" -Name $PropertyName -PropertyType $PropertyType -Value $Value -Force | Out-Null
                if ((Get-ItemProperty -Path "HKU:\$SID\$KeyPath" -ErrorAction silentlycontinue).$PropertyName -eq $Value) {
                    Write-Verbose "Successfully set new property value..."
                    Write-Verbose "Already loaded Test: True"
                    $Result = $true
                }
            }
        }
        else {
            $Proc = Start-Process reg -ArgumentList @("load","HKU\$SID","C:\Users\$UserAccount\NTUSER.DAT") -PassThru -Wait -NoNewWindow
            if (Test-Path -Path "HKU:\$SID\$KeyPath") { 
                if ([String]::IsNullOrEmpty((Get-ItemProperty -Path "HKU:\$SID\$KeyPath" -ErrorAction silentlycontinue).$PropertyName)) {
                    Write-Verbose "Creating new property..."
                    New-ItemProperty -Path "HKU:\$SID\$KeyPath" -Name $PropertyName -PropertyType $PropertyType -Value $Value -Force | Out-Null
                }
                else {
                    Write-Verbose "Setting new property value..."
                    Set-ItemProperty -Path "HKU:\$SID\$KeyPath" -Name $PropertyName -Value $Value -Force | Out-Null
                }
                if ((Get-ItemProperty -Path "HKU:\$SID\$KeyPath" -ErrorAction silentlycontinue).$PropertyName -eq $Value) {
                    Write-Verbose "Successfully set new property value..."
                    Write-Verbose " Not Already loaded Test: True"
                    $Result = $true
                }
                else {
                    Write-Verbose "Not Already loaded Test: False" ; $Result = $false
                }
            }
            else {
                Write-Verbose "Creating Path ""\$KeyPath""  for ""$UserAccount"""
                New-Item -Path ("HKU:\$SID\$KeyPath" | Split-Path -Parent) -Name ("$KeyPath" | Split-Path -Leaf) -ItemType Directory -Force | Out-Null
                Write-Verbose "Creating new property..."
                New-ItemProperty -Path "HKU:\$SID\$KeyPath" -Name $PropertyName -PropertyType $PropertyType -Value $Value -Force | Out-Null
                if ((Get-ItemProperty -Path "HKU:\$SID\$KeyPath" -ErrorAction silentlycontinue).$PropertyName -eq $Value) {
                    Write-Verbose "Successfully set new property value..."
                    Write-Verbose "Not Already loaded Test: True"
                    $Result = $true
                }
            }
        }
    }
    End {
        if ($Proc.ExitCode -eq 0) {
            $UnloadRegProc = Start-Process reg -ArgumentList @("unload","HKU\$SID") -PassThru -Wait -NoNewWindow
            $Count = 0
            while (($UnloadRegProc.ExitCode -ne 0) -and ($Count -lt 30)) {
                $UnloadRegProc = Start-Process reg -ArgumentList @("unload","HKU\$SID") -PassThru -Wait -NoNewWindow
                Start-Sleep -Seconds 1
                $Count++
                Write-Verbose "Waiting for successful unload: $Count"
            }
            if ($UnloadRegProc.Exitcode -eq 1) {
                Write-Verbose "Reg Unload Exited: ""$($UnloadRegProc.ExitCode)"""
            }
        }
        Remove-PSDrive HKU | Out-Null
        if ($Result) {
            Return $true
        }
        else {
            Return $false
        }    
    }
}

Function Get-UserReg{
[CmdletBinding()]
Param(
        [ValidateScript({Test-Path -Path "$env:HOMEDRIVE\Users\$_"})]
        [Parameter( Position=1,
                    Mandatory=$true
                    )]$UserAccount,
        [Parameter( Position=2,
                    Mandatory=$true
                    )]$KeyPath,
        [Parameter( Position=3,
                    Mandatory=$true
                    )]$PropertyName,
        [Parameter( Position=4,
                    Mandatory=$true
                    )]$Value
      )
Begin{
      $User = New-Object System.Security.Principal.NTAccount("$UserAccount")
      $SID = $User.Translate([System.Security.Principal.SecurityIdentifier]).value
      New-PSDrive HKU Registry HKEY_USERS | Out-Null
      If (
          (Get-ChildItem -Path "HKU:\" | select -ExpandProperty Name) -contains "HKEY_USERS\$SID"
          ){
            $Loaded = $true
            }
      else{$Loaded = $false}
      Write-Verbose "$SID"
      }
Process{
        If (
            $Loaded
            ){
                If (
                    Test-Path -Path "HKU:\$SID\$KeyPath"
                    ){
                        If (
                            (Get-ItemProperty -Path "HKU:\$SID\$KeyPath" -ErrorAction silentlycontinue).$PropertyName -eq $Value
                            ){
                               Write-Verbose "Already loaded Test: True"
                               $Result = $true
                              }
                        else{Write-Verbose "Already loaded Test: False" ; $Result = $false}
                      }
                Else{Write-Verbose "Path ""\$KeyPath"" does not Exist for ""$UserAccount"""}
              }
        Else{
             $Proc = Start-Process reg -ArgumentList @("load","HKU\$SID","C:\Users\$UserAccount\NTUSER.DAT") -PassThru -Wait -NoNewWindow
             If (
                 Test-Path -Path "HKU:\$SID\$KeyPath"
                 ){ 
                     If (
                         (Get-ItemProperty -Path "HKU:\$SID\$KeyPath" -ErrorAction silentlycontinue).$PropertyName -eq $Value
                         ){
                            Write-Verbose "Not Already loaded Test: True"
                            $Result = $true
                           }
                     else{Write-Verbose "Not Already loaded Test: False"; $Result = $false}
                   }
             else{Write-Verbose "Path ""\$KeyPath"" does not Exist for ""$UserAccount"""}
             }
        }
End{
    If (
        $Proc.ExitCode -eq 0
        ){
           $UnloadRegProc = Start-Process reg -ArgumentList @("unload","HKU\$SID") -PassThru -Wait -NoNewWindow
           $Count = 0
           While (
                  ($UnloadRegProc.ExitCode -ne 0) -and ($Count -lt 10)
                  ){
                    $UnloadRegProc = Start-Process reg -ArgumentList @("unload","HKU\$SID") -PassThru -Wait -NoNewWindow
                    Start-Sleep -Seconds 1
                    $Count++
                    Write-Verbose "Waiting for successful unload: $Count"
                    }
           If ($UnloadRegProc.Exitcode -eq 1){Write-Verbose "Reg Unload Exited: ""$($UnloadRegProc.ExitCode)"""}
          }
    Remove-PSDrive HKU | Out-Null
    If ($Result){Return $true}
    Else{Return $false}    
    }
}

#endregion Functions Section

#region Assign Script Variables: CHANGE THESE

#region SPECIFY REGISTRY KEY TO CREATE UPON SUCESS
#Change value to released date
$PCIRegPath     = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{D0C7E3F1-4A13-479C-9B7A-E623182CA901}"
$PCIRegProperty = "Secure Registry Key Updates"
$PCIRegType     = "String"
$PCIRegValue    = "2018.12"
#endregion          



#endregion Script Variables

#region Registry Modifications


#region Disable RC4 Cipher ACAS 65821
$RC4Types = 'RC4 128/128','RC4 40/128','RC4 56/128'
$RC4reg   = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
$RC4key   = 'Enabled'
$RC4Val   = '0'
$RC4Note  = 'Disable RC4 Cipher per ACAS 65821'

$PKB      = 'ACAS 65821. DISABLE RC4 Cipher'

#region Write Registry Key
foreach ($Type in $RC4Types) {
    if (!(Test-Path -Path ($RC4reg + '\'+ $Type))) {
        (Get-Item -Path $RC4reg).OpenSubKey("Ciphers", $true).CreateSubKey($Type)
        New-ItemProperty -Path ($RC4reg + "\Ciphers\"+ $Type) -Name $RC4key -Value $RC4Val -Force | Out-Null
        Write-Log "Setting new Registry property value for: ""$RC4reg`Ciphers\$Type"" -Name ""$RC4key"" -Value ""$RC4Val""" -Level Info

        if (((Get-ItemProperty -Path ($RC4reg+'\Ciphers\'+ $Type) -ErrorAction SilentlyContinue).$RC4key -Match '0')) {
            Write-Log "Registry Key applied successfully." -Level Success
        }
        else {
            Write-Log "Registry Key failed to apply. Please check $ScriptLog for required key settings.$RC4Note" -Level Info
        }                 
    }
}

#region Install PCI Registry Key
if ($RegistryChangeKey) {
    New-Item -Path $RegistryChangeKey -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -Path $RegistryChangeKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
    if ((Test-Path -Path $RegistryChangeKey) -and ((Get-ItemProperty -Path $RegistryChangeKey).$PKB -match 'Installed')) {
        Write-Log -Message "Registered ""$RegistryChangeKey"" Property: ""$PKB"" Value: ""Installed""." -Level Info
    }
}
#endregion Install PCI Registry Key

#endregion Disable RC4 Cipher ACAS 65821

#region Resolves missing registry key value for Insecure Library Loading. ACAS 48762
$Key      = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
$Property = 'CWDIllegalInDllSearch'
$Type     = 'DWord'
$Value    = '1'
$Note     = 'ACAS 48762. Fix for Insecure Library Loading.'

$PKB = $Note
#region Write Registry Key
# if not exist or set incorrectly, force create/overwrite the key with the correct value
if (!(Get-ItemProperty -Path $Key -name $Key -ErrorAction SilentlyContinue) -or !((Get-ItemProperty -Path $Key).$Property -Match $Value)) {
    Write-Log "System requires registry setting to FIX Cached logon count." -Level Info
    Write-Log "Applying registry Fix." -Level Info
    New-ItemProperty -Path $Key -Name $Property -PropertyType $Type -Value $Value -Force | Out-Null

    # query to validate correctly set value.
    if (((Get-ItemProperty -Path $Key).$Property -Match $Value)) {
        Write-Log "Applied Registry Key. ""$Note"". ""$Key"" ""$Property"". Value:""$Value""" -Level Success

        #region Install PCI Registry Key
        if ($RegistryChangeKey) {
            New-Item -Path $RegistryChangeKey -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path $RegistryChangeKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
            if ((Test-Path -Path $RegistryChangeKey) -and ((Get-ItemProperty -Path $RegistryChangeKey).$PKB -match 'Installed')) {
                Write-Log -Message "Registered ""$RegistryChangeKey"" Property: ""$PKB"" Value: ""Installed""." -Level Info
            }
        }
        #endregion Install PCI Registry Key
    }
    else {
        Write-Log "Unable to apply Registry Key. Please check or manually update: Registry Key:""$Key"" Property:""$Property"" Value:""$Value""" -Level Error
    }
}
else {
    Write-Log """$Note"" has already been applied." -Level Info
}
#endregion Write Registry Key

#endregion Resolves missing registry key value for Insecure Library Loading. ACAS 48762

#region Fixes SSL vulnerability server settings "POODLE". ACAS 78447
$Key      = 'HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0'
$Property = 'Enabled'
$Value    = '0'
$Type     = 'DWord'
$Note     = 'ACAS 78447.SSL 3.0 Vulnerability (POODLE) FIX'

#If not exist or set incorrectly, force create/overwrite the key with the correct value
if (!(Test-Path -Path $Key)) {
    Write-Log "The System is missing a required registry value for fixing SSL 3.0 Vulnerability 'POODLE'."
    Write-Log "Applying Registry setting to FIX SSL 3.0 Vulnerability 'POODLE'"
    Write-Log "Creating Registry Key: $SSLReg" -Level Info
    New-Item -Path $Key  | Out-Null
    Write-Log "Creating Registry Key: ""$Key\Server""" -Level Info
    New-Item -Path $Key\Server  | Out-Null
    Write-Log "Creating Registry Key: ""$Key\Client""" -Level Info
    New-Item -Path $Key\Client  | Out-Null
    Write-Log "Setting new Registry property value for: $SSLReg\Server -Name $Property -Value $Value" -Level Info
    New-ItemProperty -Path $Key\Server -Name $Property -PropertyType $Type -Value $Value -Force  | Out-Null
    Write-Log "Setting new Registry property value for: $SSLReg\Server -Name $Property -Value $Value" -Level Info
    New-ItemProperty -Path $Key\Client -Name $Property -PropertyType $Type -Value $Value -Force  | Out-Null
}
#Query to validate correctly set value.
if (((Get-ItemProperty -Path $Key\Server).$Property -Match $Value) -and ((Get-ItemProperty -Path $Key\Client).$Property -Match $Value)) {
    Write-Log "Registry Key applied successfully.  ""$Key\Server"" ""Enabled"" = '0'." -Level Success
    Write-Log "Registry Key applied successfully.  ""$Key\Client"" ""Enabled"" = '0'." -Level Success
}
else {
    Write-Log "Registry Key failed to apply. Please check $ScriptLog for required key settings." -Level Error
}

#region Install PCI Registry Key
if ($RegistryChangeKey) {
    New-Item -Path $RegistryChangeKey -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -Path $RegistryChangeKey -Name "$Note" -PropertyType String -Value "Installed" -Force | Out-Null
    if ((Test-Path -Path $RegistryChangeKey) -and ((Get-ItemProperty -Path $RegistryChangeKey).$Note -match 'Installed')) {
        Write-Log -Message "Registered ""$RegistryChangeKey"" Property: ""$Note"" Value: ""Installed""." -Level Info
    }
}
#endregion Install PCI Registry Key

#endregion Fixes SSL vulnerability server settings "POODLE". ACAS 78447

#region Fixes SIDEBAR Vulnerability. ACAS 59915
$Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar'
$Property = 'TurnOffSidebar'
$Value = '1'
$Note = 'ACAS 59915. Fix for SIDEBAR Vulnerability.'

$PKB = $Note
#If not exist or set incorrectly, force create/overwrite the key with the correct value
if (!((Get-ItemProperty -Path $Key -ErrorAction SilentlyContinue).$Property)) {
    Write-Log "The System is missing a required registry value for $Note" -Level Warn
    Write-Log "Applying Registry setting to fix Windows Sidebar Vulnerability. ACAS 59915." -Level Info
    New-ItemProperty -Path $Key -Name $Property -PropertyType "DWord" -Value $Value -Force | Out-Null
    if (((Get-ItemProperty -Path $Key).$Property -Match '1')) {
        Write-Log "Applied registry key: ""$Key"" Property: ""$Property"" Value:""$Value""." -Level Success
        #region Install PCI Registry Key
        if ($RegistryChangeKey) {
            New-Item -Path $RegistryChangeKey -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path $RegistryChangeKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
            if ((Test-Path -Path $RegistryChangeKey) -and ((Get-ItemProperty -Path $RegistryChangeKey).$PKB -match 'Installed')) {
                Write-Log -Message "Registered ""$RegistryChangeKey"" Property: ""$PKB"" Value: ""Installed""." -Level Info
            }
        }
        #endregion Install PCI Registry Key
    }
    else {
        Write-Log "FAILED to apply registry key. ""$Key"" Property: ""$Property"" Value:""$Value""." -Level Error
    }
}
if (((Get-ItemProperty -Path $Key -ErrorAction SilentlyContinue).$Property -Match '1')) {
    Write-Log "The correct registry key and value already exist.  $Key $Property Value =""$Value""." -Level Info
}
#endregion Fixes SIDEBAR Vulnerability. ACAS 59915

#region Enables DotNet STIG Requirements APPNET
Write-Log "Checking User Registry keys for required Dot Net STIG Values." -Level Info
#define the non administrative account.
$UserNote = 'DotNet Framework STIG Compliance'
$PKB = $UserNote

#region Set DEFAULT User Value
if ((Get-PSDrive | select -ExpandProperty Name) -notcontains "HKU") {
    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
}

$KeyPath = "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing"
$PropertyName = 'State'
$PropertyType = 'DWORD'
$Value = '146432'

# if not exist or set incorrectly, force create/overwrite the key with the correct value
if (((Get-ItemProperty -Path $KeyPath).$PropertyName -notmatch '146432')) {
    Write-Log "System is missing a required registry value for DotNet Framework STIG Compliance." -Level Info
    Write-Log "Applying Registry setting to comply with DotNet STIG" -Level Info
    if ([String]::IsNullOrEmpty((Get-ItemProperty -Path $KeyPath).$PropertyName)) {
        New-ItemProperty -Path $KeyPath -Name $PropertyName -PropertyType $PropertyType -Value $Value -Force
    }
    else {
        Set-ItemProperty -Path $KeyPath -Name $PropertyName -Value $Value -Force
    }
}
else {
    Write-Log """DEFAULT"" profile is already compliant with ""$UserNote""." -Level Info
}

if ((Get-PSDrive | select -ExpandProperty Name) -contains "HKU") {
    Remove-PSDrive -Name HKU
}
#endregion Set DEFAULT User Value

#region Set for all other users
$KeyPath = "Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing"
$PropertyName = 'State'
$PropertyType = 'DWORD'
$Value = '146432'

#region Stop Non-BuiltIn Services
$NonBuiltInSvcAccounts = (Get-WmiObject -Class Win32_Service | Where-Object {$_.StartName -ne 'LocalSystem'} | Where-Object {$_.StartName -ne 'NT Authority\NetworkService'}| Where-Object {$_.StartName -ne 'NT AUTHORITY\LocalService'} | Select -ExpandProperty StartName | Sort-Object -Unique)

foreach ($SVCAccount in ($NonBuiltInSvcAccounts | Split-Path -Leaf)) {
    foreach ($service in (Get-WmiObject -Class Win32_Service | Where-Object {$_.StartName -match $SVCAccount})) {
        Write-Host -object ("Stopping service " + '"'+ $service.name + '"')
        Stop-Service -Name $service.name -Force
    }
}
#endregion Stop Non-BuiltIn Services

$UserProfiles = (Get-ChildItem -Path "$Env:Homedrive\Users" | Where-Object {$_.Name -ne 'Public'} | Where-Object {$_.Name -ne 'DEFAULT'})
foreach ($UserProfile in $UserProfiles) {
    #Get-UserReg -UserAccount "$($UserProfile.Name)" -KeyPath "Software\Test" -PropertyName "TestString" -Value "TestValue2" -Verbose
    $Results = Get-UserReg -UserAccount "$($UserProfile.Name)" -KeyPath $KeyPath -PropertyName $PropertyName -Value $Value -Verbose
    if ($Results) {
        Write-Log """$($UserProfile.Name)"" profile is already compliant with ""$UserNote""." -Level Info
    }
    else {
        Write-Log "Updating ""$($UserProfile.Name)"" profile to meet ""$UserNote""." -Level Info
        Set-UserReg -UserAccount "$($UserProfile.Name)" -KeyPath $KeyPath -PropertyName $PropertyName -PropertyType $PropertyType -Value $Value -Verbose
        $Results = Get-UserReg -UserAccount "$($UserProfile.Name)" -KeyPath $KeyPath -PropertyName $PropertyName -Value $Value -Verbose

        if ($Results) {
            Write-Log """$($UserProfile.Name)"" profile is now compliant with ""$UserNote""." -Level Info
        }
        else {
            Write-Log "Failed to update ""$($UserProfile.Name)"" profile to meet ""$UserNote""." -Level Error
        }
    }
}
#endregion Set for all other users

#region Install PCI Registry Key
if ($RegistryChangeKey) {
    New-Item -Path $RegistryChangeKey -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -Path $RegistryChangeKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
    if ((Test-Path -Path $RegistryChangeKey) -and ((Get-ItemProperty -Path $RegistryChangeKey).$PKB -match 'Installed')) {
        Write-Log -Message "Registered ""$RegistryChangeKey"" Property: ""$PKB"" Value: ""Installed""." -Level Info
    }
}
#endregion Install PCI Registry Key

#endregion Enables DotNet STIG Requirements APPNET

#region FIX .NET Strong Name Validation. V-30935
Write-Log "Checking Registry keys for required values." -Level Info
#Setting registry path variable
$Key      = 'HKLM:\SOFTWARE\Microsoft\.NETFramework'
$Property = 'AllowStrongNameBypass'
$Type     = 'DWord'
$Value    = '0'
$Note     = 'V-30935 Fix .NET to validate strong names.'

$PKB = $Note

#region Write Registry Key
if ([String]::IsNullOrEmpty((Get-ItemProperty -Path $Key).$Property)) {
    Write-Log "The System is missing a required registry value for $Note" -Level Warn
    Write-Log "Applying Registry setting." -Level Info
    New-ItemProperty -Path $Key -Name $Property -PropertyType DWORD -Value $Value
}
# if not exist or set incorrectly, force create/overwrite the key with the correct value
elseif (![String]::IsNullOrEmpty((Get-ItemProperty -Path $Key).$Property) -and !((Get-ItemProperty -Path $Key).$Property -Match $Value)) {
    Write-Log "The System is missing a required registry value for $Note" -Level Warn
    Write-Log "Applying Registry setting." -Level Info
    Set-ItemProperty -Path $Key -Name $Property -Value $Value -Force | Out-Null
}
# Query to validate correctly set value.
if (((Get-ItemProperty -Path $Key).$Property -Match $Value)) {
    Write-Log "Applied Registry Key. ""$Note"". ""$Key"" ""$Property"". Value:""$Value""" -Level Success
       
    #region Install PCI Registry Key
    if ($RegistryChangeKey) {
        New-Item -Path $RegistryChangeKey -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path $RegistryChangeKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
        if ((Test-Path -Path $RegistryChangeKey) -and ((Get-ItemProperty -Path $RegistryChangeKey).$PKB -match 'Installed')) {
            Write-Log -Message "Registered ""$RegistryChangeKey"" Property: ""$PKB"" Value: ""Installed""." -Level Info
        }
    }
    #endregion Install PCI Registry Key
}
else {
    Write-Log "FAILED to apply Registry Key. Please check or manually update: Registry Key:""$Key"" Property:""$Property"" Value:""$Value""" -Level Error
}
#endregion Write Registry Key

#endregion FIX .NET Strong Name Validation. V-30935

#region Fix Unquoted Service paths ACAS 63155
$SvcPaths1 = (([System.IO.Path]::GetTempPath()) + 'SvcPaths1(Before).csv')
$SvcPaths2 = (([System.IO.Path]::GetTempPath()) + 'SvcPaths2(After).csv')
$Scripts = "$TempDirectory\PSScripts\Get-SVCPath.ps1","$TempDirectory\PSScripts\Find-BADSVCPath.ps1","$TempDirectory\PSScripts\Fix-BADSVCPath.ps1"

$PKB = 'ACAS 63155. Fix for Unquoted Service Paths.'

if ((Test-Path -Path "$TempDirectory\PSScripts\Get-SVCPath.ps1") -and (Test-Path -Path "$TempDirectory\PSScripts\Find-BADSVCPath.ps1") -and (Test-Path -Path "$TempDirectory\PSScripts\Fix-BADSVCPath.ps1")) {
    Write-Log "Scripts to resolve Unquoted Services Paths have been detected." -Level Info
    Write-Log "Beginging to resolve Unquoted Service Paths." -Level Info
    Set-Location -Path $TempDirectory
    $BadKeyCheck = .\PSScripts\Get-SVCPath.ps1 | .\PSScripts\Find-BADSVCPath.ps1

    if (($BadKeyCheck | Select -ExpandProperty BadKey) -contains "yes") {
        Write-Log "Unquoted Service paths found..." -Level Info
        Write-Log "Exporting current service paths to ""$SvcPaths1""" -Level Info
        .\PSScripts\Get-SVCPath.ps1 | .\PSScripts\Find-BADSVCPath.ps1 | Export-Csv -Path $SvcPaths1
        Write-Log "Fixing affected service paths." -Level Info
        .\PSScripts\Get-SVCPath.ps1 | .\PSScripts\Find-BADSVCPath.ps1 | .\PSScripts\Fix-BADSVCPath.ps1 | Out-Null
        Write-Log "Exporting fixed service paths to ""$SvcPaths2""" -Level Info
        .\PSScripts\Get-SVCPath.ps1 | .\PSScripts\Find-BADSVCPath.ps1 | Export-Csv -Path $SvcPaths2
        Start-Sleep -Milliseconds 500
        $FixedKeyVerify = Import-Csv -Path $SvcPaths2
    }
    else {
        Write-Log "No Unquoted Service paths found." -Level Info
    }
    if (![string]::IsNullOrEmpty($FixedKeyVerify) -and !($FixedKeyVerify.BadKey -contains "yes")) {
        Write-Log "Fixed affected service paths." -Level Info
        #region Install PCI Registry Key
        if ($RegistryChangeKey) {
            New-Item -Path $RegistryChangeKey -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path $RegistryChangeKey -Name "$PKB" -PropertyType String -Value "Installed" -Force | Out-Null
            if ((Test-Path -Path $RegistryChangeKey) -and ((Get-ItemProperty -Path $RegistryChangeKey).$PKB -match 'Installed')) {
                Write-Log -Message "Registered ""$RegistryChangeKey"" Property: ""$PKB"" Value: ""Installed""." -Level Info
            }
        }
        #endregion Install PCI Registry Key
    }
    elseif (![string]::IsNullOrEmpty($FixedKeyVerify) -and $FixedKeyVerify.Badkey -contains "yes") {
        Write-Log "FAILED to fix affected service paths. Please check ""$SvcPaths2"" for remaining unquoted service paths." -Level Error
    }
}
#endregion Fix Unquoted Service paths ACAS 63155

#endregion Registry Modifications

#region Disable SMBv1 ACAS 96982
if ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" | select -ExpandProperty 'SMB1') -eq 0) {
    Write-Log "No change required. ""SMB1"" is already set to ""0"" in ""HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters""." -Level Info
}
else {
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" -Name SMB1 -PropertyType DWORD -Value 0 -Force

    if ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" | select -ExpandProperty 'SMB1') -eq 0) {
        Write-Log "Added ""SMB1"" to ""HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters"" with value of ""0""" -Level Success
    }
    else {
        Write-Log "Unable to add ""SMB1"" to ""HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters"" with value of ""0""" -Level Error
    }
}

$item1 = "Bowser"
$item2 = "MRxSmb20"
$item3 = "NSI"
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" /v "DependOnService" /t REG_MULTI_SZ /d $item1\0$item2\0$item3 /f

if ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" | select -ExpandProperty 'Start') -eq 4) {
    Write-Log "No change required. ""Start"" is already set to ""4"" in ""HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10""." -Level Info
}
else {
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name Start -PropertyType DWORD -Value 4 -Force

    if ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" | select -ExpandProperty 'Start') -eq 4) {
        Write-Log "Added ""Start"" to ""HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"" with value of ""4""" -Level Success
    }
    else {
        Write-Log "Unable to add ""Start"" to ""HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"" with value of ""4""" -Level Error
    }
}
#endregion

#region Apply new reg changes #ADDED 30OCT2018
$localpath = "$TempDirectory\Registry.csv"

Import-Csv $localpath -Header "ValueName","Key","Data","Type","Note" | ForEach-Object {

$value = $_.ValueName
$key = $_.Key
$data = $_.Data
$type = $_.Type
$note = $_.Note

    if ( ($value -eq "ValueName") -and ($key -eq "Key") -and ($data -eq "Data") -and ($type -eq "Type") -and ($note -eq "Note") ) {
        Write-Log "Updating Registry" -Level Info
    }
    else {
        if ($data -eq "noentry") {
            $data = ""
        }             
            if (!(Test-Path -Path $key)) {

                New-Item -Path ($key | Split-Path -Parent) -Name ($key | Split-Path -Leaf) -ItemType Registry
            
            }
   
             if ((Get-ItemProperty -Path $key).$value -eq $data){
                
                 Write-Log "'$key' property '$value' with value of '$data' has already been set. No changes have been made. $note" -Level Info
                
                }
                
                else { 
                   
                    New-ItemProperty -Path $key -Name $value -PropertyType $type -Value $data  -Force              
                
                 if ((Get-ItemProperty -Path $key).$value -eq $data){
                     
                     Write-Log "Created new registry $key property '$value' with value of '$data'. $note" -Level Success
                     
                     }

                     else {
                       
                       Write-Log "Failed to apply registry $key $value" -Level Warn
                      
                         }
         }
    }
} #apply registries
#endregion Apply new reg changes #ADDED 30OCT2018

#endregion Registry Modifications





