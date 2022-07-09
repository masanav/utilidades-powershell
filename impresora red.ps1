$PrinterIP = "1.2.3.4"
#$PrinterPort = "5678"
$DriverName = "Nombre driver"
#$DriverPath = "C:\Temp\impresora"
$DriverInf = "C:\Temp\impresora\controaldor_x64.inf"

$PrinterPortName = "Casa_" + $PrinterIP
$PrinterCaption = $PrinterPortName

pnputil.exe /a $DriverInf
Add-PrinterDriver -Name $DriverName
Get-Printer $PrinterCaption -ErrorAction SilentlyContinue | Remove-Printer
Get-PrinterPort $PrinterPortName -ErrorAction SilentlyContinue | Remove-PrinterPort
Add-PrinterPort -Name $PrinterPortName -PrinterHostAddress $PrinterIP -SNMP 1 -SNMPCommunity "public"
Add-Printer -DriverName $DriverName -Name $PrinterCaption -PortName $PrinterPortName -Verbose