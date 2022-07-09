function getInventario($rutafichero) {
    $ordenador = Get-WmiObject -Class Win32_ComputerSystem | Select-Object  -Property Domain, Manufacturer, Model, Name
    $ordenadorInfo = @()
    foreach ($item in $ordenador) {
        $pc = $null
        $pc = New-Object PSObject -Property @{
            Dominio = $item.Domain
            Modelo  = If ($item.Model -contains $item.Manufacturer) { ($item.Model) }Else { ($item.Model -join " " -join $item.Manufacturer) }
            Nombre  = $item.Name
        }
        $ordenadorInfo += $pc
    }
    $ordenadorInfo | Out-String | Where-Object { $null -ne $_.trim() -or "" -ne $_.trim() } | Set-Content -Path $rutafichero
   
   
    $bios = Get-WmiObject -Class Win32_BIOS | Select-Object -Property SerialNumber
    $biosInfo = @()
   
    foreach ($item in $bios) {
        $pieza = $null
        $pieza = New-Object PSObject -Property @{
            NºSerieBios = $item.SerialNumber
        }
        $biosInfo += $pieza
    }
    $biosInfo | Out-String | Where-Object { $null -ne $_.trim() -or "" -ne $_.trim() } | Add-Content -Path $rutafichero
     
      
    $monitores = Get-WmiObject -Namespace root\wmi -Class wmiMonitorID | Select-Object -Property UserFriendlyName, SerialNumberID, PSComputerName
    $monitorInfo = @()
    foreach ($item in $monitores) {
        $mon = $null
        $mon = New-Object PSObject -Property @{
            Monitor = ($item.UserFriendlyName | % { [char]$_ }) -join ''
            NºSerie = ($item.SerialNumberID | % { [char]$_ }) -join ''
        }
   
        $monitorInfo += $mon
    }
    $monitorInfo | Out-String | Where-Object { $null -ne $_.trim() -or "" -ne $_.trim() } | Add-Content -Path $rutafichero
   
   
    $impresoras = Get-WmiObject -Class Win32_Printer  | Select-Object -Property DeviceID, PortName
    $impresorasInfo = @()
    foreach ($item in $impresoras) {
        $impre = $null
        $impre = New-Object PSObject -Property @{
            Impresora = ($item.DeviceID)
            Puerto    = ($item.PortName)
        }
        if ($item.DeviceID -eq "Fax") {
            continue
        }
        $impresorasInfo += $impre
    }
    $impresorasInfo | Out-String | Where-Object { $null -ne $_.trim() -or "" -ne $_.trim() } | Add-Content -Path $rutafichero
   
   
    $discos = Get-WmiObject -Class Win32_DiskDrive | Select-Object -Property Model, Size
    $discosInfo = @()
    foreach ($item in $discos) {
        if ($item.Size -gt 0) {
            $disc = $null
            $disc = New-Object PSObject -Property @{
                Disco = $item.Model
                Peso  = [string][int](($item.Size / [Math]::Pow(1024, 3))) + [string]" GB"
            }
            $discosInfo += $disc
        }
    }
    $discosInfo | Out-String | Where-Object { $null -ne $_.trim() -or "" -ne $_.trim() } | Add-Content -Path $rutafichero
   
   
    $memoria = Get-WmiObject -Class win32_physicalmemory | Select-Object -Property Manufacturer, PartNumber, SerialNumber, Capacity, Speed
    $memoriaInfo = @()
    foreach ($item in $memoria) {
        $pieza = $null
        $pieza = New-Object PSObject -Property @{
            Memoria   = $item.Manufacturer
            Modelo    = $item.PartNumber
            NºSerie   = $item.SerialNumber
            Velocidad = [string]$item.Speed + [string]" Mhz"
            Peso      = [string][int](($item.Capacity / [Math]::Pow(1024, 3))) + [string]" GB"
        }
        $memoriaInfo += $pieza
    }
    $memoriaInfo | Out-String | Where-Object { $null -ne $_.trim() -or "" -ne $_.trim() } | Add-Content -Path $rutafichero
   
   
    $adaptador = Get-WmiObject  -Class Win32_NetworkAdapterConfiguration | Select-Object -Property Index, SettingID, MACAddress, IPSubnet, DNSHostName, DefaultIPGateway, DHCPServer, DNSServerSearchOrder, IPAddress, Description
    $adaptadorInfo = @()
    foreach ($item in $adaptador) {
        if ($null -eq $item.IPAddress -or "" -eq $item.IPAddress) {
            continue
        }
        $pieza = $null
        $pieza = New-Object PSObject -Property @{
            Adaptador = $item.Description
            IP        = $item.IPAddress
            Mascara   = $item.IPSubnet
            Puerta    = $item.DefaultIPGateway
            DNS       = $item.DNSServerSearchOrder
            DHCP      = $item.DHCPServer
            MAC       = $item.MACAddress
        }
        $adaptadorInfo += $pieza
    }
    $adaptadorInfo | Out-String | Where-Object { $null -ne $_.trim() -or "" -ne $_.trim() } | Add-Content -Path $rutafichero
}
   
function checkRuta($fichero) {
    $rutaarray = $fichero.Split("\")
    $rutacarpeta = ""
   
    for ($num = 0; $num -lt $rutaarray.Length - 1; $num++) {
        $rutacarpeta += $rutaarray[$num] + "\"
    }
    $rutacarpeta
    
   
   
    if (-not (Test-Path -LiteralPath $rutacarpeta)) {
       
        try {
            New-Item -Path $rutacarpeta -ItemType Directory -ErrorAction Stop | Out-Null #-Force
        }
        catch {
            return $False
            Write-Error -Message "Unable to create directory '$rutacarpeta'. Error was: $_" -ErrorAction Stop
        }
    }
    return $True
   
}
   
$fichero = "C:\TEMP\inventario.txt"
$carpetaExiste = checkRuta($fichero)
if ($carpetaExiste) {
    getInventario($fichero)
    Get-Content($fichero)
}