# Install programs
	Write-Output "Literka pendriva"
	$PathDrive = Read-Host -AsString

	Start-Process -FilePath $PathDrive':\new computers\app\AcroRdrDC1800920044_pl_PL.exe' -wait
	Start-Process -FilePath $PathDrive':\new computers\app\AdobeAIRInstaller.exe' -wait
	Start-Process -FilePath $PathDrive':\new computers\app\install_flash_player.exe' -wait
	Start-Process -FilePath $PathDrive':\new computers\app\LibreOffice_6.0.0_Win_x86.msi' -wait
	Start-Process -FilePath $PathDrive':\new computers\app\QVPluginWin8andUp.exe' -wait
	Start-Process -FilePath $PathDrive':\new computers\app\qvpluginsetup.exe' -wait
	Start-Process -FilePath $PathDrive':\new computers\app\Silverlight_x64.exe' -wait
	Start-Process -FilePath $PathDrive':\new computers\app\VC_redist.x64.exe' -wait
	#Start-Process -FilePath $PathDrive':\new computers\app\Office2k16STD\setup.exe' -wait
	Start-Process -FilePath $PathDrive':\new computers\app\zzzzERA_Installer_x64_pl_PL-lapki z netem.exe' -wait
