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





