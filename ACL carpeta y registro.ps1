$Usuario = "Usuario"
$RutaCarpeta = "C:\TEMP\Carpeta"
$TipoPermiso = "FullControl"
$Permiso = "Allow"

$ACL = Get-ACL -Path $RutaCarpeta
#$ACL.Access | Format-Table
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($Usuario, $TipoPermiso, $Permiso)
$ACL.SetAccessRule($AccessRule)
#$ACL.Access | Format-Table


$RutaRegistro = "HKLM:\SOFTWARE\Carpeta"

$ACL = Get-ACL -Path $RutaRegistro
$AccessRule = New-Object System.Security.AccessControl.RegistryAccessRule($Usuario, $TipoPermiso, $Permiso)
$ACL.SetAccessRule($AccessRule)