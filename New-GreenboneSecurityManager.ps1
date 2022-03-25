$workdir = "$env:temp\gsm"

#
# download latest GSM
#
$uri = 'https://files.greenbone.net/download/delivery/f535c003-97f7-4917-9f4a-21d8c0cca785/GSM-TRIAL-21.04.13-VirtualBox.ova'
$ova = Join-Path $workdir $($uri.Substring($uri.LastIndexOf("/") + 1))
#$uri = Read-Host "URL of Greenbone Security Manager in VirtualBox format"
Start-BitsTransfer -Source "$uri" -Destination "$ova"

#
# extract vmdk file from ova
#
cd $workdir
tar -x -f $ova *.vmdk

#
# download tool used to convert vmdk to vhdx
#
$uri = 'https://cloudbase.it/downloads/qemu-img-win-x64-2_3_0.zip'
$zip = Join-Path $workdir $($uri.Substring($uri.LastIndexOf("/") + 1))
Start-BitsTransfer -Source "$uri" -Destination "$zip"
Expand-Archive $zip -DestinationPath .

#
# convert vmdk to vhdx
#
$src = (Get-Item *.vmdk).FullName
$dst = $src.Replace('vmdk','vhdx')
& .\qemu-img.exe convert $src -O vhdx -o subformat=dynamic $dst

Write-Output "Virtual hard disk file is available at $dst"

##Compress-Archive -Path $dst -DestinationPath $dst.Replace('vhdx','zip')

[System.IO.Compression.ZipFile]::CreateFromDirectory(".", $dst.Replace('vhdx','zip'))