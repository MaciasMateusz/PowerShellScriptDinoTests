Write-Output "Podaj nazwe komputera"
	$PCName = Read-Host -AsString

	Write-Output "Podaj imie i nazwisko"
	$UserName = Read-Host -AsString
	
	New-SmbShare –Name Skany –Path C:\Skany –FullAccess Wszyscy

	$OSValues = Get-WmiObject -class Win32_OperatingSystem -computername $PCName
	$OSValues.Description = $UserName
	$OSValues.put()