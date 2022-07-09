function Get-JavaInstalados($RutaJava) {
    $RutaJava = 'C:\Program Files\Java'
    $CarpetasJava = (Get-ChildItem -LiteralPath $RutaJava)
    $CarpetasValidas = [System.Collections.ArrayList] @()
    foreach ($item in $CarpetasJava) {
        $cadena = [string] $item
        if ($cadena -ne 'jre6') {
            $CarpetasValidas.Add($cadena)
        }
    }
    return "$RutaJava\$($CarpetasValidas[-1])\bin\javaw.exe"
}

function Get-BitPlataforma () {
    if ([Environment]::Is64BitProcess -eq $True) {
        return $true
    }
    return $false
}

function Set-RutaJava ($64bit) {
    if ($64bit -eq $True) {
        return 'C:\Program Files\Java'
    }
    return 'C:\Program Files (x86)\Java'
}

function Admin-Shorcut {
    PARAM (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 0)] [system.string] $RutaEXE,
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 1)] [system.string] $RutaDestino,
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 2)] [system.string] $RutaTrabajo,
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 3)] [system.string] $RutaIcono,
        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 4)] [system.string] $Argumentos
    )
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($RutaDestino)
    $Shortcut.TargetPath = $RutaEXE
    $Shortcut.Arguments = $Argumentos
    $Shortcut.IconLocation = $RutaIcono
    $Shortcut.WorkingDirectory = $RutaTrabajo
    $Shortcut.Save()

    #bit de administrador
    #$bytes = [System.IO.File]::ReadAllBytes($RutaDestino)
    #$bytes[0x15] = $bytes[0x15] -bor 0x20
    #[System.IO.File]::WriteAllBytes($RutaDestino, $bytes)
}

$64bit = Get-BitPlataforma ($null)
$RutaJava = Set-RutaJava($64bit)
$PathJavaW = Get-JavaInstalados($RutaJava)
$PathJavaW = $PathJavaW | Where-Object { $_.length -gt 2 }

$RutaDondePoner = 'C:\Users\Usuario\Desktop\Acceso.lnk'
$Argumentos = ''
Admin-Shorcut $PathJavaW $RutaDondePoner "C:\CarpetaPrograma" "%SystemDrive%\CarpetaPrograma\icons\app.ico" $Argumentos