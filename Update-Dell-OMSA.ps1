$ver = "8.3"
$url = "http://downloads.dell.com/FOLDER03600970M/2/OM-SrvAdmin-Dell-DUP_381KW_WIN64-8.3.0_1908_A00.EXE"
$exe = ".\OM-SrvAdmin-Dell-DUP_381KW_WIN64-8.3.0_1908_A00.EXE"
$prm = "/s"

$about = omreport about

if ($about | Select-String $ver) {
  Write-Host "Dell OMSA is already version $ver"
} else {
  Write-Host "Dell OMSA needs to be upgraded to version $ver"
  Invoke-WebRequest $url -OutFile $exe
  Write-Host "Upgrading Dell OMSA using $exe $prm"
  & $exe $prm | Out-Host
  Write-Host "Removing $exe"
  Remove-Item $exe
}

omconfig preferences webserver attribute=ciphers setting=TLS_RSA_WITH_AES_128_CBC_SHA
omconfig preferences webserver attribute=sslprotocol setting=TLSv1.2
omconfig system webserver action=restart
