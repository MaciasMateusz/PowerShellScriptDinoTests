Write-Output "Podaj imie i nazwisko"
	$UserName = Read-Host -AsString
	
	Write-Output "Podaj poczatek maila"
	$Mail = Read-Host -AsString

	Write-Output "GOLD port"
	$GOLD = Read-Host -AsString

	(Get-Content $PathDrive':\new computers\podpisth.html' ) -replace 'sample',$UserName | Set-Content $env:USERPROFILE'\Moje dokumenty\podpisth.html'
	
	(Get-Content $PathDrive':\new computers\ThunderbirdConfig\prefs.js' ) -replace 'sample',$Mail | Set-Content $env:USERPROFILE'\AppData\Roaming\Thunderbird\Profiles\*.default\prefs.js'

	(Get-Content $env:USERPROFILE'\AppData\Roaming\Thunderbird\Profiles\*.default\prefs.js' ) -replace 'sampleFULL',$Username | Set-Content $env:USERPROFILE'\AppData\Roaming\Thunderbird\Profiles\*.default\prefs.js'
