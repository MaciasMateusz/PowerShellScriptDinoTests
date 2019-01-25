# Read data
	Write-Output "Podaj nazwe komputera"
	$PCName = Read-Host -AsString

	Write-Output "Podaj imie i nazwisko"
	$UserName = Read-Host -AsString

	DO {
		Write-Output "Podaj haslo uzytkownika"
		$Password = Read-Host -AsSecureString

    		Write-Output "Podaj haslo uzytkownika ponownie"
		$PasswordTemp = Read-Host -AsSecureString

    		$Password_txt = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
   		$PasswordTemp_txt = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordTemp))

    	} While ($Password_txt -ne $PasswordTemp_txt)

	DO {
		Write-Output "Podaj haslo admina"
		$PasswordAdmin = Read-Host -AsSecureString

    		Write-Output "Podaj haslo admina ponownie"
		$PasswordAdminTemp = Read-Host -AsSecureString

    		$PasswordAdmin_txt = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordAdmin))
   		$PasswordAdminTemp_txt = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordAdminTemp))

    	} While ($PasswordAdmin_txt -ne $PasswordAdminTemp_txt)

	Write-Output "Literka pendriva"
	$PathDrive = Read-Host -AsString

	Write-Output "Model"
	$Model = Read-Host -AsString

	Write-Output "VPN nazwa"
	$VPN = Read-Host -AsString

	

# Add to members, enable Administrator account, rename computer, add description
	Write-Output "Add to members, enable Administrator account, rename computer, add description..."
	Rename-Computer -NewName $PCName
	Add-Computer -WorkGroupName "DINO_MAGAZYN"
	Add-LocalGroupMember -Group "Użytkownicy pulpitu zdalnego" -Member $UserName
	Add-LocalGroupMember -Group "Operatorzy konfiguracji sieci" -Member $UserName
	Add-LocalGroupMember -Group "Użytkownicy" -Member $UserName

	Enable-LocalUser -Name "Administrator"
	Set-LocalUser -Name "Administrator" -Password $PasswordAdmin

	Remove-LocalGroupMember -Group "Administratorzy" -Member $UserName
	Set-LocalUser -Name $UserName -Password $Password -UserMayChangePassword 0
	Add-LocalGroupMember -Group "Administratorzy" -Member $UserName
	
# Create shortcuts, folder Skany
	Write-Output "Create shortcuts, folder Skany..."
	$WshShell = New-Object -ComObject WScript.Shell
	$Shortcut = $WshShell.CreateShortcut("$Home\Desktop\DINOPANEL3.url")
	$Shortcut.TargetPath = "http://dinopanel3.dino.intranet/"
	$Shortcut.Save()

	$WshShell = New-Object -ComObject WScript.Shell
	$Shortcut = $WshShell.CreateShortcut("$Home\Desktop\XPRIMER.url")
	$Shortcut.TargetPath = "http://xprimer.dino.intranet:8070/xprimer/start"
	$Shortcut.Save()

	$WshShell = New-Object -ComObject WScript.Shell
	$Shortcut = $WshShell.CreateShortcut("$Home\Desktop\DINOPANEL.url")
	$Shortcut.TargetPath = "http://dinopanel.dino.intranet/"
	$Shortcut.Save()

	New-Item -ItemType directory -Path C:\Skany

	$wshshell = New-Object -ComObject WScript.Shell
	$desktop = [System.Environment]::GetFolderPath('Desktop')
	  $lnk = $wshshell.CreateShortcut($desktop+"\Skany.lnk")
	  $lnk.TargetPath = "c:\Skany"
	  $lnk.Save()

# Show This PC shortcut on desktop
	Write-Output "Showing This PC shortcut on desktop..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0

# Disable Windows Firewall
	Write-Output "Disable Windows Firewall..."
	Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Internet option configuration
 	Write-Output "Internet option configuration..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\New Windows" -Name "PopupMgr" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name "2500" -Type DWord -Value 3

# Show User Folder shortcut on desktop
    Write-Output "Showing User Folder shortcut on desktop..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0

# Unpin all Start Menu tiles - Note: This function has no counterpart. You have to pin the tiles back manually.
	Write-Output "Unpinning all Start Menu tiles..."
	If ([System.Environment]::OSVersion.Version.Build -ge 15063 -And [System.Environment]::OSVersion.Version.Build -le 16299) {
		Get-ChildItem -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount" -Include "*.group" -Recurse | ForEach-Object {
			$data = (Get-ItemProperty -Path "$($_.PsPath)\Current" -Name "Data").Data -Join ","
			$data = $data.Substring(0, $data.IndexOf(",0,202,30") + 9) + ",0,202,80,0,0"
			Set-ItemProperty -Path "$($_.PsPath)\Current" -Name "Data" -Type Binary -Value $data.Split(",")
		}
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 17134) {
		$key = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*start.tilegrid`$windows.data.curatedtilecollection.tilecollection\Current"
		$data = $key.Data[0..25] + ([byte[]](202,50,0,226,44,1,1,0,0))
		Set-ItemProperty -Path $key.PSPath -Name "Data" -Type Binary -Value $data
		Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
	}


# Disable Fast Startup
	Write-Output "Disabling Fast Startup..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0

# Adjusts visual effects for performance - Disables animations, transparency etc. but leaves font smoothing and miniatures enabled
	Write-Output "Adjusting visual effects for performance..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 0
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0))
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0
	Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0

# Enable Remote Desktop w/o Network Level Authentication
	Write-Output "Enabling Remote Desktop w/o Network Level Authentication..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 0
	Enable-NetFirewallRule -Name "RemoteDesktop*"
	Add-LocalGroupMember -Group "Użytkownicy pulpitu zdalnego" -Member "Wszyscy"

#Genarate documents
	$Serial = wmic bios get serialnumber
	$Date = [datetime]::Today.ToString('dd.MM.yyy')
	Copy-Item -Path $PathDrive':\new computers\documents\sample.txt' -destination $PathDrive':\new computers\documents\'$UserName'.txt'
	(Get-Content $PathDrive':\new computers\documents\'$UserName'.txt' ) -replace 'UserName',$UserName | Set-Content $PathDrive':\new computers\documents\'$UserName'.txt'
	(Get-Content $PathDrive':\new computers\documents\'$UserName'.txt' ) -replace 'Date',$Date | Set-Content $PathDrive':\new computers\documents\'$UserName'.txt'
	(Get-Content $PathDrive':\new computers\documents\'$UserName'.txt' ) -replace 'Model',$Model | Set-Content $PathDrive':\new computers\documents\'$UserName'.txt'
	(Get-Content $PathDrive':\new computers\documents\'$UserName'.txt' ) -replace 'Serial',$Serial | Set-Content $PathDrive':\new computers\documents\'$UserName'.txt'

# Import cerificate
	Import-Certificate -Filepath $PathDrive":\new computers\app\ca_poczta.crt" -CertStoreLocation "cert:\CurrentUser\Root"

# Silence intall programs
	Start-Process $PathDrive':\new computers\app\Firefox Setup 63.0.3' '/S'
	Start-Process $PathDrive':\new computers\app\Thunderbird Setup 52.8.0' '/S'
	Start-Process $PathDrive':\new computers\app\7z1801-64bit' '/S'
	Start-Process $PathDrive':\new computers\app\openvpn-install-2.3.14-I601-x86_64' '/S'
	Start-Process $PathDrive':\new computers\app\tightvnc-2.8.11-gpl-setup-64bit.msi' '/quiet'
	Start-Process $PathDrive':\new computers\app\GOLD - Javy\jre-6u25-windows-x64' '/quiet'
	Start-Process $PathDrive':\new computers\app\GOLD - Javy\jre-6u25-windows-i586' '/quiet'

# Install .NET Framework 2.0, 3.0 and 3.5 runtimes - Requires internet connection
	Write-Output "Installing .NET Framework 2.0, 3.0 and 3.5 runtimes..."
	If ((Get-WmiObject -Class "Win32_OperatingSystem").Caption -like "*Server*") {
		Install-WindowsFeature -Name "NET-Framework-Core" -WarningAction SilentlyContinue | Out-Null
	} Else {
		Enable-WindowsOptionalFeature -Online -FeatureName "NetFx3" -NoRestart -WarningAction SilentlyContinue | Out-Null
	}

# Permission VPN
	$folder = "C:\Program Files\OpenVPN"
	$myGroup = "użytkownicy"
	$acl = Get-Acl $folder
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$myGroup", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
	$acl.AddAccessRule($rule)
	Set-Acl $folder $acl

	$folder = "C:\Program Files\OpenVPN"
	$myGroup = "operatorzy konfiguracji sieci"
    	$acl = Get-Acl $folder
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$myGroup", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
	$acl.AddAccessRule($rule)
	Set-Acl $folder $acl

	$folder = "C:\Users\Public\Desktop\OpenVPN GUI.lnk"
	$myGroup = "użytkownicy"
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$myGroup", "FullControl", "Allow")
	$acl.AddAccessRule($rule)
	Set-Acl $folder $acl

	$folder = "C:\Users\Public\Desktop\OpenVPN GUI.lnk"
	$myGroup = "operatorzy konfiguracji sieci"
    	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$myGroup", "FullControl", "Allow")
	$acl.AddAccessRule($rule)
	Set-Acl $folder $acl

	Copy-Item -Path $PathDrive':\new computers\config\*' -Destination 'C:\Program Files\OpenVPN\config'

	(Get-Content "C:\Program Files\OpenVPN\config\Marketdino_VPN.ovpn" ) -replace 'edydynska',$VPN | Set-Content "C:\Program Files\OpenVPN\config\Marketdino_VPN.ovpn"
	

