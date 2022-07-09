$NombreProgramas = 'Programa 1', 'Programa 2'


foreach ($Item in $NombreProgramas) {
    $ClaveDesinstalador = Get-WmiObject -Class Win32_Product -Filter "Name = '$Item'" | Select-Object -Expand IdentifyingNumber 
    if ($ClaveDesinstalador) {
        Write-Output ("Desinstalando " + $Item)
        msiexec /passive /x $ClaveDesinstalador | Out-Null
    }
}