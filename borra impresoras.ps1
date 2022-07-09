$ImpresorasParaBorrar = "impresora1", "impresora2"

$ImpresorasInstaladas = Get-Printer | select name

foreach ($impresora in $ImpresorasInstaladas) {
    if ($ImpresorasParaBorrar -contains $impresora.Name) {
        Remove-Printer -Name $impresora.Name
        Write-Output ('Borrada ' + $impresora.Name)
    }
}