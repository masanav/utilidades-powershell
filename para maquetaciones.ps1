$PrefijoHostName = ""
$dominio = 'dominio.root'
$Localhost = [System.Net.Dns]::GetHostName()
$NombreFicheroOU = "ou.txt"
$NombreFicheroInfo = "inventario.txt"
$RutaFicheroInfo = ''
$RutaFicheroOU = ''

function Get-Credenciales {
    $usuario = Read-Host -Prompt "Introduce tu usuario"
    $clave = Read-Host -Prompt "Clave" -AsSecureString
    $clave = ConvertTo-SecureString $clave -AsPlainText -Force

    $Credenciales = New-Object System.Management.Automation.PSCredential ($usuario, $clave)
    #$credenciales | Export-CliXml -Path 'C:\temp\acred.xml'
    return $Credenciales
}

function Check-CarpetaComienzaPor ($PrefijoHostName) {
    $CarpetaActual = $PSCommandPath.split('\')[-2]
    $NombreScript = $PSCommandPath.split('\')[-1]
    #Write-Host ('Ejecutado ' + $CarpetaActual)

    if ($CarpetaActual -like "$PrefijoHostName*" -and $CarpetaActual.Length -eq 15) {
        $RutaFicheroInfo = "$PSScriptRoot\$NombreFicheroInfo"
        $RutaFicheroOU = "$PSScriptRoot\$NombreFicheroOU"
        Main-Programa ($Credenciales)
        return
    }
    elseif ($CarpetaActual -like "$PrefijoHostName*" -and $CarpetaActual.Length -ne 15) {
        Write-Error ('El nombre de máquina no es estándar')
        Pause
    }
    else {
        if ($Localhost -like "$PrefijoHostName*" -and $Localhost.Length -eq 15) {
            New-Item -Path $Localhost -ItemType Directory -ErrorAction SilentlyContinue | Out-Null #-Force
            $RutaDestinoCarpetaScript = $PSScriptRoot + '\' + $Localhost
            Copy-Item -Path $PSCommandPath -Destination $RutaDestinoCarpetaScript -Force -Confirm:$false
            $RutaDestinoScript = ("$RutaDestinoCarpetaScript\$NombreScript")
            $RutaFicheroInfo = "$RutaDestinoCarpetaScript\$NombreFicheroInfo"
            $RutaFicheroOU = "$RutaDestinoCarpetaScript\$NombreFicheroOU"
            &$RutaDestinoScript
            return

        }
        elseif ($Localhost -like "$PrefijoHostName*" -and $Localhost.Length -ne 15) {
            Write-Warning ('El nombre de máquina no es estándar')
            Write-Warning ('Si vas a maquetar el equipo, no merece la pena renombrar el equipo en este momento')
            Write-Warning ('Crea la carpeta a mano con el nombre BUENO que debe llevar y copia el script en ella')
            Pause
        }
    }
    return
}

function Show-Direccionador () {
    $opcion = ''
    #Clear-Host
    Write-Warning ('La mayoría de funciones requieren usar cuenta de administrador local e iniciar el script con tu usuario de dominio')
    $Title = 'Principal'
    Write-Host "================ $Title ================"
    
    Write-Host "1: Dominio."
    Write-Host "2: Conexiones Wifis."
    Write-Host "3: Perfiles."
    Write-Host "4: Guardar inventario ordenador."
    Write-host "5: Renombrar ordenador."
    Write-Host "6: Reconfigurar interfaces de red."
    Write-host "7: Reinstalar impresoras."
    Write-host "8: Habilitar administradores."
    Write-host "9: Unidades de red."
    Write-Host "10: Reiniciar el equipo."
    Write-Host "S: Salir."
    $opcion = Read-Host -Prompt "Selección"

    return $opcion
}

function Set-Direccionador ($Credenciales) {
    $opcion = ''
    $opcion = Show-Direccionador($null)
    while ($opcion -ne 's' -and $opcion -ne 'S') {
        switch ($opcion) {
            '1' {
                Caso_1_Dominio ($Credenciales)
                break
            }'2' {
                Caso_2_Conexiones_Wifi ($Credenciales)
                break
            }'3' {
                Caso_3_PerfilesWindows ($Credenciales)
                break
            }'4' {
                Caso_4_GuardarInventario ($null)
                break
            }'5' {
                Caso_5_RenombrarOrdenador ($null)
                break
            }'6' {
                Caso_6_ReconfigurarInterfacesRed ($null)
                break
            }'7' {
                Caso_7_ReinstalarImpresoras($null)
                break
            }'8' {
                Caso_8_HabilitarAdministradores ($null)
                break
            }'9' {
                Caso_9_UnidadesRed ($null)
                break
            }'10' {
                Restart-Computer -Force -Confirm:$false
                break
            }($_ -eq 's' -or $_ -eq 'S') {
                Write-Host ('Hasta pronto')
                return
            }default {
                Write-Host ('Mala opción')
            }
        }
        $opcion = Show-Direccionador($null)
    }
}

function Caso_1_Dominio ($Credenciales) {
    $opcion = ''
    $Menu = @"
    1: Borrar OU guardada.
    2: Guardar OU actual.
    3: Sacar de dominio.
    4: Unir a dominio.
    5: Volver al menú principal
"@
    do {
        Write-Host ($Menu)
        $opcion = Read-Host -Prompt "Selección"
        $opcion
        switch ($opcion) {
            '1' {
                Remove-Item -Path $RutaFicheroOU
                break
            }'2' {
                Caso_1a_Guarda_OU_actual($null)
                break
            }'3' {
                Caso_1b_Meter_Grupo_Trabajo($Credenciales)
                break
            }'4' {
                Caso_1c_Meter_Dominio($Credenciales)
                break
            }'5' {
                Check-CarpetaComienzaPor ($PrefijoHostName)
                break
            }default {
                Write-Host ('Mala opción')
                break
            }
        }
        $opcion = Show-Direccionador($null)
    }while ($opcion -gt '0' -and $opcion -lt '6')
}

function Caso_1a_Guarda_OU_actual() {
    $GuardarOU = Get-ItemPropertyValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine' -Name Distinguished-Name
    $ArrayListOU = [System.Collections.ArrayList] ($GuardarOU.Split(','))
    $ArrayListOU.RemoveAt(0)
    $ArrayListOU = "$ArrayListOU".replace(' ', ',')
    $ArrayListOU
    Set-Content -Value $ArrayListOU -Path $RutaFicheroOU
}

function Caso_1b_Meter_Grupo_Trabajo($Credenciales) {
    #$Credenciales=Set-CredencialesFalsas($null)
    $booleano_grupotrabajo = Comprobar-GrupoDeTrabajo($null)

    if ($booleano_grupotrabajo -ne $false) {
        Write-Host ("Sacando de dominio...")
        try {
            Remove-Computer -UnjoinDomainCredential $Credenciales -WorkgroupName "xd" -Force -ErrorAction Stop
        }
        catch [System.InvalidOperationException] {
            Write-Warning ('No se puede quitar el dominio de un equipo que no tiene dominio')
        }
        finally {
            #Get-Errores ($Error[0])
        }
        
        Write-Host ("Eliminando el equipo de dominio...")
        try {
            Remove-ADComputer -Identity $Localhost -Confirm:$false
        }
        catch [System.Management.Automation.CommandNotFoundException] {
            Write-Warning ('El equipo no tiene las RSAT para eliminarle del AD. Tienes que eliminarlo a manija')
        }
        finally {
            #Get-Errores ($Error[0])
        }

        Write-Host ("Forzando el grupo de trabajo")
        try {
            Add-Computer -Credential $Credenciales -WorkGroupName "xd" -Force -ErrorAction Stop
        }
        catch [System.InvalidOperationException] {
            Write-Warning ('El equipo ya esta en ese grupo de trabajo. Reinicia o realiza otra operación')
        }
        finally {
            #Get-Errores ($Error[0])
        }
    }
    else {
        Write-Host ('Equipo ya en grupo de trabajo')
    }
}

function Caso_1c_Meter_Dominio($Credenciales) {
    #cls
    $booleano_grupotrabajo = Comprobar-GrupoDeTrabajo($null)
    Write-Host ("Dominio: " + $booleano_grupotrabajo)
    $booleano_ping_nombre_equipo = Comprobar-PingNombreEquipo($null)
    Write-Host ("Ping:" + $booleano_ping_nombre_equipo)
    $OUs = ''
    
    if ($booleano_grupo -eq $false ) {
        Write-Host ("Equipo en dominio. Si quieres lo sacas, y si no ya lo tienes")
        #}elseif($booleano_ping_nombre_equipo -eq $true){
        #    Write-Host ("Nombre de equipo repetido. Cambia el hostname")
    }
    else {
        Write-Output "Para meter en dominio"
        if (Test-Path -LiteralPath $RutaFicheroOU) {
            if ((Get-Content $RutaFicheroOU).Length -gt 0) {
                $OUs = Get-Content $RutaFicheroOU
                Write-Host ('Leido')
            }
            else {
                Write-host ('No leido')
                $OUs = Set-OUs ($null)
            }
        }
        else {
            Write-Host ('else')
            $OUs = Set-OUs ($null)
        }
        $ValoresEnviados = [System.Collections.ArrayList]@()
        $ValoresEnviados.Add($Credenciales)
        $ValoresEnviados.Add($OUs)
        Set-Dominio ($ValoresEnviados)
    }
}

function Caso_2_Conexiones_Wifi ($Credenciales) {
    $opcion
    $Menu = @"
    1: Conectar Wifi 1
    2: Eliminar Wifi 1
    3: Conectar Wifi 2
    4: Eliminar Wifi 2
    5: Volver al menú principal
"@
    do {
        Write-Host ($Menu)
        $opcion = Read-Host -Prompt "Selección"
        $opcion
        switch ($opcion) {
            '1' {
                $guid = New-Guid
                $Base64XMLConfigRedWifi = ''
                $PerfilRed = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($Base64XMLConfigRedWifi))
                $PerfilRed | out-file "$($ENV:TEMP)\$guid.SSID"

                netsh wlan add profile filename="$($ENV:TEMP)\$guid.SSID" user=all
                remove-item "$($ENV:TEMP)\$guid.SSID" -Force
                break
            }'2' {
                netsh wlan delete profile name='1'
                break
            }'3' {
                $guid = New-Guid
                $Base64XMLConfigRedWifi = ''
                $PerfilRed = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($Base64XMLConfigRedWifi))
                $PerfilRed | out-file "$($ENV:TEMP)\$guid.SSID"

                netsh wlan add profile filename="$($ENV:TEMP)\$guid.SSID" user=all
                remove-item "$($ENV:TEMP)\$guid.SSID" -Force
                break
            }'4' {
                netsh wlan delete profile name='2'
                break
            }'5' {
                Check-CarpetaComienzaPor ($PrefijoHostName)
                break
                #opción de desarrollo para copiar la config del xml de la red wifi y pasarlo a base64
            }'7' {
                Write-Host ('Codificando')
                $plano = @"
texto a codificar
"@
                $Bytes = [System.Text.Encoding]::Unicode.GetBytes($plano)
                $EncodedText = [Convert]::ToBase64String($Bytes)
                $EncodedText
                break
            }default {
                Write-Host ('Default')
                break
            }
        }
        
    }while ($opcion -gt '0' -and $opcion -lt '9')
}

function Caso_3_PerfilesWindows ($Credenciales) {
    $opcion = ''
    Write-host "7: Borrar perfiles."
    Write-host "10: Copiar perfiles."
    $Menu = @"
    1: Borrar perfiles.
    2: Copiar perfiles.
    3: Borrar perfiles temporales.
    4: Volver al menú principal
"@
    do {
        Write-Host ($Menu)
        $opcion = Read-Host -Prompt "Selección"
        $opcion
        switch ($opcion) {
            '1' {
                Caso_3a_BorrarPerfilesWindows ($False)
                break
            }'2' {
                Caso_3b_CopiarPerfiles ($null)
                break
            }'3' {
                Caso_3a_BorrarPerfilesWindows ($True)
                break
            }'4' {
                Check-CarpetaComienzaPor ($PrefijoHostName)
                break
            }default {
                Write-Host ('Mala opción')
                break
            }
        }
        $opcion = Show-Direccionador($null)
    }while ($opcion -gt '0' -and $opcion -lt '6')
}

function Caso_3a_BorrarPerfilesWindows ($SoloTemporales) {
    Write-Warning ('Si hay sesiones abiertas, el script borrar la mayor parte de las carpetas, pero se requiere un reinicio posterior y borrar las carpetas de usuarios restantes')
    Cerrar_sesion_usuarios ($null)
    $PerfilesExcluidosDeBorrarPerfiles = "Invitado", "Administrador"
    $RutaCarpetasPerfilesEnUsoEnEquipo = Get-WMIObject -class Win32_UserProfile | Where-Object { ($_.Loaded -and ($_.SID -match '^S-1-5-21-\d+-\d+-\d+-\d+$')) }


    #$WMIperfiles = Get-WMIObject -class Win32_UserProfile | Where-Object { (!$_.Loaded -and ![System.String]::IsNullOrWhiteSpace($_.LastUseTime) ) }
    $RutaBaseRamaUsuarios = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\'
    $PerfilesEnRegistro = Get-ItemProperty ('Registry::' + $RutaBaseRamaUsuarios + '\*')
    $RutaBaseCarpetaUsuarios = 'C:\Users\'
    $CarpetasUsuarios = Get-ChildItem $RutaBaseCarpetaUsuarios

    $CarpetasPerfilesEnUsoEnEquipo = New-Object System.Collections.ArrayList
    $NombresCarpetasUsuariosEnUso = $RutaCarpetasPerfilesEnUsoEnEquipo | Select LocalPath

    #añade usuario a arraylist de usuarios con sesión iniciada
    foreach ($item in $NombresCarpetasUsuariosEnUso) {
        try {
            $CarpetasPerfilesEnUsoEnEquipo.Add($item.LocalPath.split('\\')[-1])
        }
        catch {
            Write-Host ('Error ' + $item)
        }
    }

    Write-Host ('-------------EN USO-------------')
    Write-Host ($CarpetasPerfilesEnUsoEnEquipo)
    Write-Host ('--------------------------------')

    #Borra carpetas de usuarios
    for ($Contador = 0; $Contador -lt $CarpetasUsuarios.Length; $Contador++) {
        $Carpeta = $CarpetasUsuarios[$Contador]
        try {
            $EsUsuarioTemporal = Is-UsuarioTemporal ($Carpeta)
            Write-Host ("Es temporal $EsUsuarioTemporal")
            Write-Host ("Temporales $SoloTemporales")
            if ($CarpetasPerfilesEnUsoEnEquipo -notcontains $Carpeta -and $PerfilesExcluidosDeBorrarPerfiles -notcontains $Carpeta) {
                if ($SoloTemporales -eq $False -or ($SoloTemporales -eq $true -and $EsUsuarioTemporal -eq $true)) {
                    try {
                        $ruta = ($RutaBaseCarpetaUsuarios + $Carpeta)
                        $NumeroArchivos = ((Get-ChildItem -Recurse) | Measure-Object).Count
                        Write-Progress -Activity "Borrando carpeta de perfil $Carpeta" -Status "Perfil $($Contador+1) de $($CarpetasUsuarios.Length) con $NumeroArchivos archivos"
                        #Write-warning ("Borrado $Carpeta")
                        #Remove-Item -Path $ruta -Recurse -Forc
                        cmd /c rmdir /s /q $ruta
                        cmd /c del /f /s /q $ruta
                    }
                    catch {
                        Get-Errores ($Error[0])
                    }
                }
            }
        }
        catch {
            Write-Host ('Error de carpeta ' + $Carpeta)
        }
    }

    Write-Warning ('Parte de registro')
    for ($Contador = 0; $Contador -lt $PerfilesEnRegistro.Length; $Contador++) {
        $PerfilRegistro = $PerfilesEnRegistro[$Contador]

        try {
            $NombreUsusario = ($PerfilRegistro.ProfileImagePath).Split('\')[-1]
            $EsUsuarioTemporal = Is-UsuarioTemporal ($NombreUsusario)

            if ($RutaCarpetasPerfilesEnUsoEnEquipo -notcontains $NombreUsusario -and $PerfilesExcluidosDeBorrarPerfiles -notcontains $NombreUsusario) {
                if ($SoloTemporales -eq $False -or ($SoloTemporales -eq $true -and $EsUsuarioTemporal -eq $true)) {
                    try {
                        Remove-Item -Path ('Registry::' + $RutaBaseRamaUsuarios + $PerfilRegistro.PSChildName) -Force -Confirm:$false
                        #Write-Output ('Borrado registro ' + $RutaBaseRamaUsuarios + $PerfilRegistro.PSChildName)
                        Write-Progress -Activity "Usuario $NombreUsusario borrado de registro" -Status "Perfil $($Contador+1) de $($PerfilesEnRegistro.Length)"
                    }
                    catch {
                        Get-Errores ($Error[0])
                    }
                }
            }
        }
        catch {
            Write-Host ('Error de registro ' + $PerfilRegistro)
            if ($PerfilRegistro.PSobject.Properties.name -notmatch "ProfileImagePath") {
                Remove-Item -Path ('Registry::' + $RutaBaseRamaUsuarios + $PerfilRegistro.PSChildName) -Force -Confirm:$false
            }
        }
    }
}

function Caso_3b_CopiarPerfiles () {
    #Set-Content -Value $BatUnidadesRed -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\unidades_personales.bat"
    #Write-Host ('Script copiado')

    $ChildPerfiles = Get-ChildItem 'C:\Users\' -ErrorAction Stop
    $ListaCarpetas = $ChildPerfiles | ForEach-Object { $_.Name }
    #$ListaCarpetas
    #foreach ($Carpeta in $ListaCarpetas) {
    for ($Contador = 0; $Contador -lt $ListaCarpetas.Length; $Contador++) {
        $Carpeta = $ListaCarpetas[$Contador]
        Write-Progress -Activity "Copiando perfil $Carpeta" -Status "Perfil $($Contador+1) de $($ListaCarpetas.Length)" -PercentComplete ($($Contador + 1) / $($ListaCarpetas.Length) * 100)
        $RutaPerfil = "C:\Users\$Carpeta\"
        Write-Host ("$PSScriptRoot\Users\$Carpeta")
        try {
            Copy-Item -Path "$RutaPerfil\Downloads" -Destination "$PSScriptRoot\Users\$Carpeta\Downloads" -Recurse -ErrorAction SilentlyContinue
            Copy-Item -Path "$RutaPerfil\Pictures" -Destination "$PSScriptRoot\Users\$Carpeta\Pictures" -Recurse -ErrorAction SilentlyContinue
            Copy-Item -Path "$RutaPerfil\Music" -Destination "$PSScriptRoot\Users\$Carpeta\Music" -Recurse -ErrorAction SilentlyContinue
            Copy-Item -Path "$RutaPerfil\Videos" -Destination "$PSScriptRoot\Users\$Carpeta\Videos" -Recurse -ErrorAction SilentlyContinue
            Copy-Item -Path "$RutaPerfil\Desktop" -Destination "$PSScriptRoot\Users\$Carpeta\Desktop" -Recurse -ErrorAction SilentlyContinue
            Copy-Item -Path "$RutaPerfil\Documents" -Destination "$PSScriptRoot\Users\$Carpeta\Documents" -Recurse -ErrorAction SilentlyContinue
            Copy-Item -Path "$RutaPerfil\Favorites" -Destination "$PSScriptRoot\Users\$Carpeta\Favorites" -Recurse -ErrorAction SilentlyContinue
        }
        catch [System.UnauthorizedAccessException] {
            Get-Errores ($Error[0])
            Write-Warning ('No se puede copiar el archivo. quizá este en uso')
        }
        catch [System.IO.IOException] {
            Write-Warning ('No se encuentra la ruta')
            Get-Errores ($Error[0])
        }
    }
}

function Caso_4_GuardarInventario () {
    Write-Host ('Inventario ' + $RutaFicheroInfo)
    $Equipo = New-Object PSObject -Property @{
        NombreEquipo = ($Localhost)
    }
    Set-Content -Value $Equipo -Path $RutaFicheroInfo

    $adaptadores = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Select-Object -Property Description, IPAddress, MACAddress, IPSubnet, DefaultIPGateway
    $adaptadorInfo = @()
    foreach ($item in $adaptadores) {
        if ($null -eq $item.IPAddress -or "" -eq $item.IPAddress) {
            continue
        }
        $descripcion = ''
        $ip = ''
        $mascara = ''
        $puerta = ''
        $mac = ''
        if ($item.Description.Length -gt 0) {
            $descripcion = $item.Description
        }
        if ($item.IPAddress.Length -gt 0) {
            $ip = $item.IPAddress[0]
        }
        if ($item.IPSubnet.Length -gt 0) {
            $mascara = $item.IPSubnet[0]
        }
        if ($item.DefaultIPGateway.Length -gt 0) {
            $puerta = $item.DefaultIPGateway[0]
        }
        if ($item.MACAddress.Length -gt 0) {
            $mac = $item.MACAddress
        }
        
        $pieza = $null
        if ($item.IPAddress.Length -gt 0) {
            $pieza = New-Object PSObject -Property @{
                Adaptador = $descripcion
                IP        = $ip
                Mascara   = $mascara
                Puerta    = $puerta
                MAC       = $mac
            }
        }

        $adaptadorInfo += $pieza
    }
    Add-Content -Value $adaptadorInfo -Path $RutaFicheroInfo


    $impresoras = Get-WmiObject -Class Win32_Printer  | Select-Object -Property DeviceID, PortName, DriverName
    $impresorasInfo = @()
    foreach ($item in $impresoras) {
        $impre = $null
        $impre = New-Object PSObject -Property @{
            Impresora  = ($item.DeviceID)
            Puerto     = ($item.PortName)
            DriverName = ($item.DriverName)
        }
        if ($item.DeviceID -eq "Fax" -or $item.DriverName -like "*OneNote*" -or $item.DriverName -like "*PDF*") {
            continue
        }
        $impresorasInfo += $impre
    }
    Add-Content -Value $impresorasInfo -Path $RutaFicheroInfo
    Write-Host ('Guardado en ' + $RutaFicheroInfo)

}

function Caso_5_RenombrarOrdenador () {
    $Contenido = ''
    $Nombre = ''
    if (Test-Path -LiteralPath $RutaFicheroInfo) {
        if ((Get-Content $RutaFicheroInfo).Length -gt 0) {
            $Contenido = Get-Content $RutaFicheroInfo
        }

    }
    if ($Contenido -ne '') {
        foreach ($item in $Contenido) {
            if ($item -like '@{NombreEquipo*') {
                $Nombre = (($item.Split('=')[1]).replace('}', '')).trim()
            }
        }
        if ($Nombre -ne '') {
            $Nombre = Read-Host -Prompt "Teclee el nuevo nombre para el equipo"
        }

        Rename-Computer -NewName $Nombre -Confirm:$False -Force
    }
}

function Caso_6_ReconfigurarInterfacesRed () {
    $Contenido = ''
    $InterfazLeida = ''

    if (Test-Path -LiteralPath $RutaFicheroInfo) {
        if ((Get-Content $RutaFicheroInfo).Length -gt 0) {
            $Contenido = Get-Content $RutaFicheroInfo
        }
    }

    if ($Contenido -ne '') {
        foreach ($item in $Contenido) {
            if ($item -like '@{Adaptador=*') {
                $InterfazLeida = $item.replace('@{', '').replace('}', '').split(';')
                #Write-Host ($InterfazLeida)
                $MacLeida = $InterfazLeida[2].split('=')[1].trim()
                if ($MacLeida.Length -gt 0) {
                    $AdaptadoresInstalados = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Select-Object -Property Description, IPAddress, MACAddress, IPSubnet, DefaultIPGateway, Index
                    foreach ($PiezaInstalada in $AdaptadoresInstalados) {
                        if ($PiezaInstalada.MACAddress -gt 0 -and $PiezaInstalada.MACAddress -eq $MacLeida) {
                            Write-Host ($PiezaInstalada)
                            Write-Host ($InterfazLeida)
                            $MascaraLeida = $InterfazLeida[3].split('=')[1].trim()
                            $IPLeida = $InterfazLeida[1].split('=')[1].trim()
                            $PuertaLeida = $InterfazLeida[4].split('=')[1].trim()
                            #$PrefijoHostNameCalculado = getCIDRNotationBySubnetmask ($MascaraLeida)

                            $NombreInterfaz = ((WMIC Path Win32_NetworkAdapter Where "MACAddress='$MacLeida'" get netconnectionid)[2]).trim()
                            if ($PuertaLeida.Length -gt 0) {
                                $comando = "netsh interface ipv4 set address name='$NombreInterfaz' static $IPLeida $MascaraLeida $PuertaLeida"
                                Invoke-Expression $comando

                                Set-DnsClientGlobalSetting -SuffixSearchList ('sufijo.dominio1', 'dominio1', 'dominio2')
                                Get-NetAdapter | Where-Object -Property InterfaceIndex -like '$PiezaInstalada.Index' | Set-DnsClientServerAddress -ServerAddresses ('1.1.1.1', '8.8.8.8')

                                Get-DnsClient | ForEach-Object {
                                    if ($_.InterfaceAlias -like 'Ethernet*') {
                                        Set-DnsClient -InterfaceIndex $_.InterfaceIndex -ConnectionSpecificSuffix 'dominio1' -RegisterThisConnectionsAddress $True -UseSuffixWhenRegistering $True
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

function Caso_7_ReinstalarImpresoras() {
    $Contenido = ''
    $RutaKyocera = 'C:\Instalador_Kyocera'

    if (Test-Path -LiteralPath $RutaKyocera) {

        if (Test-Path -LiteralPath $RutaFicheroInfo) {
            if ((Get-Content $RutaFicheroInfo).Length -gt 0) {
                $Contenido = Get-Content $RutaFicheroInfo
            }
        }
        if ($Contenido -ne '') {
            foreach ($item in $Contenido) {
                if ($item -like '@{Impresora=*') {
                    $ImpresoraLeida = $item.replace('@{', '').replace('}', '').split(';')
                    $NombreImpresora = $ImpresoraLeida[0].split('=')[1].trim()
                    $NombreDriver = $ImpresoraLeida[1].split('=')[1].trim()
                    $Puerto = $ImpresoraLeida[2].split('=')[1].trim()
                    $NombreImpresora
                    $NombreDriver
                    $Puerto
                    switch ($NombreDriver) {
                        'Kyocera TASKalfa 5550ci KX' {
                            if ([Environment]::Is64BitOperatingSystem -eq $True) {
                                Invoke-Command -FilePath '$RutaKyocera\color_directo_64.bat' -ArgumentList $Localhost
                            }
                            else {
                                Invoke-Command -FilePath '$RutaKyocera\color_directo_32.bat' -ArgumentList $Localhost
                            }
                        }'Kyocera ECOSYS M3550idn KX' {
                            if ([Environment]::Is64BitOperatingSystem -eq $True) {
                                Invoke-Command -FilePath '$RutaKyocera\negro_directo_64.bat' -ArgumentList $Localhost
                            }
                            else {
                                Invoke-Command -FilePath '$RutaKyocera\negro_directo_32.bat' -ArgumentList $Localhost
                            }
                        }'Kyocera ECOSYS P3050dn KX' {
                            if ([Environment]::Is64BitOperatingSystem -eq $True) {
                                Invoke-Command -FilePath '$RutaKyocera\p3050_64.bat' -ArgumentList $Localhost
                            }
                            else {
                                Invoke-Command -FilePath '$RutaKyocera\p3050_32.bat' -ArgumentList $Localhost
                            }
                        }'default' {
                            Write-Host ('$DriverName Impresora no soportada')
                        }
                    }
                }
            }
        }
    }
    else {
        Write-Warning ('{0} no existe' -f $RutaKyocera)
    }
}

function Caso_8_HabilitarAdministradores () {
    net user Administrador /active:yes
    net user Usuario /active:yes

    Write-Host ('Usuarios habilitados')
}

function Caso_9_UnidadesRed () {
    $BatUnidadesRed = @"
    @echo off

    NET USE L: /delete
    NET USE U: /delete

    echo .
    echo .
    echo Escriba su usuario de la forma: dominio\99888777A
    echo .

    IF NOT EXIST L:\ (
        NET USE L: \\raiz\CARPETA /persistent:no
    )

    IF NOT EXIST U:\ (
        mkdir \\raiz\users\%USERNAME%
        @NET USE U: /delete
        @NET USE U: \\raiz\users\%USERNAME% /persistent:no
    )
"@
    Set-Content -Value $BatUnidadesRed -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\conectar_unidades_personales.bat" -Force -Confirm:$False
    Write-Host ('Script copiado')
}

function Is-UsuarioTemporal ($NombreUsusario) {
    $Bandera = $null
    try {
        $NombreUsusarioArray = $NombreUsusario.split('.')

        if ($NombreUsusarioArray.Length -eq 1 -and $NombreUsusarioArray[0] -eq "TEMP") {
            $Bandera = $True
        }
        elseif ($NombreUsusarioArray.Length -eq 2 -and $NombreUsusarioArray[0] -eq "TEMP" -and $NombreUsusarioArray[1] -eq "dominio" ) {
            $Bandera = $True
        }
        elseif ($NombreUsusarioArray.Length -eq 3 -and $NombreUsusarioArray[0] -eq "TEMP" -and $NombreUsusarioArray[1] -eq "dominio" -and $NombreUsusarioArray[2].Length -eq 3 -and (Is-Int($NombreUsusarioArray[2])) -eq $True ) {
            $Bandera = $True
        }
    }
    catch {
        $Bandera = $False
    }
    return $Bandera
}

function Cerrar_sesion_usuarios () {
    try {
        $quserResult = quser
        try {
            $quserRegex = $quserResult | ForEach-Object -Process { $_ -replace '\s{2,}', ',' }
            $quserObject = $quserRegex | ConvertFrom-Csv
    
            foreach ($item in $quserObject) {
                try {
                    $Linea = ($item.PSobject.Properties.value).split(' ')
                    #Write-Host ($Linea)
                    if ($Linea[-1] -ne 'Activo') {
                        Write-Output ('Cerrar ' + $Linea[0] + ' - ' + $Linea[1])
                        logoff $Linea[1]
                    }
                }
                catch {
                    Write-Host ('Error de linea ' + $Linea)
                }
            }
        }
        catch {
            write-host ('quserResult: ' + $quserResult)
        }
    }
    catch {
        Write-Host ('No hay usuarios activos')
    }
}

function getCIDRNotationBySubnetmask([string]$subnetmask) {
    $cidr = 0
    $subnetmask.split(".") | foreach {
        switch ($_) {
            255 { $cidr += 8 }
            254 { $cidr += 7 }
            252 { $cidr += 6 }
            248 { $cidr += 5 }
            240 { $cidr += 4 }
            224 { $cidr += 3 }
            192 { $cidr += 2 }
            128 { $cidr += 1 }
            default { $cidr += 0 }
        }
    }
 
    return $cidr
}

function Is-Int([string]$Cadena) {
    [Int32]$OutNumber = $null
    try {
        if ([Int32]::TryParse($Cadena, [ref]$OutNumber)) {
            return $True
        }
        return $False
    }
    catch {
        return $False
    }
}

function Get-Errores ($Err) {
    $Err[0].Exception.GetType().FullName
    $Err[0] | fl * -Force
    <#
    Write-Host ('COGIDO')
    Write-Warning ($Err[0])
    Write-Host ('Salto')
    Write-Output ($Err[0].ScriptStackTrace)
    Write-Host ('Salto')
    Write-Output ($Err[0].InvocationInfo)
    #>
}

function Show-OUs () {
    $opcion = ''
    do {
        #Clear-Host
        $Title = 'Menú gestión OUs'
        Write-Host "================ $Title ================"
        
        Write-Host "1: Dept. 1"
        Write-Host "2: Dept. 2"
        #...
        Write-Host "100: Dept. 100"
        $opcion = Read-Host -Prompt "Selección"
        #Write-Host ('Pulsado '+$opcion)
    }until ($opcion -ne 's' -and $opcion -ne 'S')

    return $opcion
}

function Set-OUs () {
    $ValorRetorno = ''
    $opcion = ''
    do {
        $opcion = Show-OUs($null)
        switch ($opcion) {
            '1' {
                $ValorRetorno = "OU=A,OU=B,OU=C,OU=D,DC=dominio1,DC=dominio2"
                break
            }'2' {
                $ValorRetorno = "OU=AA,OU=B,OU=C,OU=D,DC=dominio1,DC=dominio2"
                break
                # ...
            }'100' {
                $ValorRetorno = "OU=L,OU=M,OU=N,DC=dominio1,DC=dominio2"
                break
            }
        }
    }while ($opcion -gt '0' -and $opcion -lt '101')
    return $ValorRetorno
}

function Set-Dominio ($ValoresRecibidos) {
    $contador = 0
    do {
        $joined = $true
        $contador++
        Write-Output ('Intento ' + $contador)
        if ($ous.Length -gt 0) {
            try {
                Add-Computer -DomainName $dominio -Credential $Credenciales -Force -OUPath $ous -Restart -ErrorAction Stop
                Write-Output "Unido"
            }
            catch [System.InvalidOperationException] {
                Write-Warning ('El equipo ya esta en dominio. Elije otra operación')
            }
            catch {
                Write-Output 'No unido'
                $joined = $false
                Write-Output $_.Exception.Message
                Start-Sleep -Seconds 60
            }
            finally {
                #Get-Errores ($Error[0])
            }
        }
        else {
            Write-Output ("OUs mala")
            $joined = $false
        }
    }until ($joined -eq 'true' -or $contador -eq 4)
}
 
function Comprobar-ConfianzaDominio () {
    return Test-ComputerSecureChannel
}

function Comprobar-GrupoDeTrabajo () {
    $datos = Get-WmiObject -Class Win32_ComputerSystem
    if ($datos.Workgroup.Length -ge 0) {
        return $true
    }
    return $false
}

function Comprobar-PingNombreEquipo () {
    $datos = ([System.Net.Dns]::GetHostName()) + "." + $dominio
    if (-not(Test-Connection -ComputerName $datos -Quiet -Count 1)) {
        return $false
    }
    return $true
}

function Main-Programa () {
    $Credenciales = Get-Credenciales($null)
    Set-Direccionador($Credenciales)
}

Check-CarpetaComienzaPor ($PrefijoHostName)

