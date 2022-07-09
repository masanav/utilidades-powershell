$SiteList = @()
$SiteList = (
    "http://ip1",
    "http://ip2:8080"
)

$UserFolders = Get-ChildItem -Path C:\users | Select-Object -ExpandProperty Name

foreach ($User in $UserFolders) {
    $RutaSeguridad = "C:\users\$User\AppData\LocalLow\Sun\Java\Deployment\security\"
    if (-not (Test-Path -LiteralPath $RutaSeguridad)) {
    
        try {
            New-Item -Path $RutaSeguridad -ItemType Directory -ErrorAction Stop | Out-Null #-Force
            foreach ($Site in $SiteList) {
                Add-Content -Path "C:\users\$User\AppData\LocalLow\Sun\Java\Deployment\security\exception.sites" -Value "$Site"
            }
        }
        catch {
            $None
        }   
    }
}