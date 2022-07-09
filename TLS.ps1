Function Set-TLS {
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$ProfileName,
        [Parameter(Mandatory = $true)]
        [Boolean]$LoadProfile,
        [Parameter(Mandatory = $false)]
        [String]$ProfileImagePath
    )
    Begin {
        $regPath = ('HKEY_USERS\{0}' -f $ProfileName)
        if ($LoadProfile) {
            $regExe = [System.Environment]::ExpandEnvironmentVariables('%SystemRoot%\System32\reg.exe')
            &$regExe LOAD $regPath $ProfileImagePath | Out-Null
        }
    }
    Process {
        # Set the AutoConfigURL proxy address
        $path = ('Registry::{0}\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -f $regPath)
        if (!(Test-Path $path)) {
            $result = New-Item -Path $path -Name 'SecureProtocols'
            $result.Handle.Close() # necessary to avoid 'Access Denied' issues on UNLOAD
        }
        Set-ItemProperty -LiteralPath $path -Name 'SecureProtocols' -Value 2720
    }
    End {
        if ($LoadProfile) {
            # GC Collect is necessary to avoid 'Access Denied' issues on UNLOAD
            [gc]::Collect()
            &$regExe UNLOAD ('HKEY_USERS\{0}' -f $ProfileName) | Out-Null
        }
    }
}

$RutaRelativa = '\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'

## Configuración global
$RegistryPath = 'HKLM:' + $RutaRelativa
$Name = 'SecureProtocols'
$Value = '2720'
$TipoReg = 'DWORD'
# Create the key if it does not exist
If (-NOT (Test-Path $RegistryPath)) {
    New-Item -Path $RegistryPath -Force | Out-Null
} 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType $TipoReg -Force

## Configuración por defecto
$RegistryPath = 'HKU:' + $RutaRelativa
# Create the key if it does not exist
If (-NOT (Test-Path $RegistryPath)) {
    New-Item -Path $RegistryPath -Force | Out-Null
} 
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType $TipoReg -Force

## Configuración por cada usuario
# Get actively logged on users and setting Autoconfig URL (willis proxy)
$activeUsers = @{}
Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.PSChildName -match '^S-1-5-21-\d+-\d+-\d+-\d+$' } | ForEach-Object { $activeUsers.Add($_.PSChildName, $null) } | Out-Null
# Set the Internet Explorer AutoConfigURL for each existing user
Get-ItemProperty 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' | Where-Object { $_.PSChildName -match '^S-1-5-21-\d+-\d+-\d+-\d+$' } |
ForEach-Object {
    Set-TLS -ProfileName $_.PSChildName -LoadProfile (!($activeUsers.ContainsKey($_.PSChildName))) -ProfileImagePath (Join-Path $_.ProfileImagePath 'NTUSER.DAT')
} | Out-Null
# Set the Internet Explorer AutoConfigURL for the default user
Set-TLS -ProfileName 'DefaultUser' -LoadProfile $true -ProfileImagePath ([System.Environment]::ExpandEnvironmentVariables('%SystemDrive%\Users\Default\NTUSER.DAT'))