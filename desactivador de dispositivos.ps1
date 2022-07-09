$Dispositivos = (Get-PnpDevice -Class "Net" -FriendlyName "*Wireless*") | Where-Object { $_.Status -contains "OK" }

foreach ($i in $Dispositivos) {
    Write-Output $i.Name, $i.InstanceId, $i.Status
    Disable-PnpDevice -InstanceId $i.InstanceId -PassThru -Confirm:$false
    Write-Output ("Desactivado " + $i.FriendlyName)
}
