Param(
    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0)][ValidateNotNullOrEmpty()][System.String]$TestOrgAPIKey
	)

. 'C:\agent\_work\1\s\ADMU\powershell\Functions.ps1'
#. 'C:\Git\support\ADMU\powershell\Functions.ps1'
#. 'C:\Users\bob.lazar.JCADB2\Downloads\support-ADMU_1.2.1\support-ADMU_1.2.1\ADMU\powershell\Functions.ps1'
	
Describe 'Functions' {

    Context 'VerifyAccount Function'{
        It 'VerifyAccount - Real Domain Account bob.lazar@JCADB2.local' {
            VerifyAccount -username bob.lazar -domain JCADB2.local | Should Be $true
        }

        It 'VerifyAccount - False Account' {
            VerifyAccount -username bob.lazar -domain JCADB2.localw | Should Be $false
        }
    }#context

    Context 'Write-Log Function'{
	
        It 'Write-Log - Log exists' {
		if ((Test-Path 'C:\Windows\Temp\jcAdmu.log') -eq $true){
                remove-item -Path 'C:\windows\Temp\jcAdmu.log' -Force
            }
            Write-Log -Message:('System is NOT joined to a domain.') -Level:('Info')
            Test-Path 'c:\windows\temp\jcAdmu.log' | Should Be $true
            #delete log file


        }

        It 'Write-Log - ERROR: Log entry exists' {
		if ((Test-Path 'C:\Windows\Temp\jcAdmu.log') -eq $true){
                remove-item -Path 'C:\windows\Temp\jcAdmu.log' -Force
            }
            Write-Log -Message:('Test Error Log Entry.') -Level:('Error')
            $Log = Get-Content 'c:\windows\temp\jcAdmu.log'
            $Log.Contains('ERROR: Test Error Log Entry.') | Should Be $true
        }

        It 'Write-Log - WARNING: Log entry exists' {
		if ((Test-Path 'C:\Windows\Temp\jcAdmu.log') -eq $true){
                remove-item -Path 'C:\windows\Temp\jcAdmu.log' -Force
            }
            Write-Log -Message:('Test Warning Log Entry.') -Level:('Warn')
            $Log = Get-Content 'c:\windows\temp\jcAdmu.log'
            $Log.Contains('WARNING: Test Warning Log Entry.') | Should Be $true
        }

        It 'Write-Log - INFO: Log entry exists' {
        if ((Test-Path 'C:\Windows\Temp\jcAdmu.log') -eq $true){
                remove-item -Path 'C:\windows\Temp\jcAdmu.log' -Force
            }
            Write-Log -Message:('Test Info Log Entry.') -Level:('Info')
            $Log = Get-Content 'c:\windows\temp\jcAdmu.log'
            $Log.Contains('INFO: Test Info Log Entry.') | Should Be $true
            remove-item -Path 'C:\windows\Temp\jcAdmu.log' -Force
        }
    }#context

    Context 'Remove-ItemIfExists Function'{
        It 'Remove-ItemIfExists - c:\windows\temp\test\' {
            if(Test-Path 'c:\windows\Temp\test\') {Remove-Item 'c:\windows\Temp\test' -Recurse -Force}
            New-Item -ItemType directory -path 'c:\windows\Temp\test\'
            New-Item 'c:\windows\Temp\test\test.txt'
            Remove-ItemIfExists -Path 'c:\windows\Temp\test\' -Recurse 
            Test-Path 'c:\windows\Temp\test\' | Should Be $false
        }
    }#context

    Context 'Add-LocalUser Function'{
        It 'Add-LocalUser - testuser to Users ' {
            net user testuser /delete | Out-Null
            net user testuser Temp123! /add
            Remove-LocalGroupMember -Group "Users" -Member "testuser"
            $WmiComputerSystem = Get-WmiObject -Class:('Win32_ComputerSystem')
            $localComputerName = $WmiComputerSystem.Name
            Add-LocalUser -computer:($localComputerName) -group:('Users') -localusername:('testuser')
            (Get-LocalGroupMember -Group 'Users' -Member 'testuser') -ne $null | Should Be $true
        }

    }#context

    Context 'Check_Program_Installed Function'{
        It 'Check_Program_Installed - Google Chrome' {
            Check_Program_Installed -programName 'Google Chrome' | Should Be $true
        }

        It 'Check_Program_Installed - Program Name Does Not Exist' {
            Check_Program_Installed -programName 'Google Chrome1' | Should Be $false
        }

    }#context

    Context 'Start-NewProcess Function'{
        It 'Start-NewProcess - Notepad' {
            Start-NewProcess -pfile:('c:\windows\system32\notepad.exe') -Timeout 2
            (Get-Process -Name 'notepad') -ne $null | Should Be $true
             Stop-Process -Name "notepad"
        }

    }#context

    Context 'Test-IsNotEmpty Function'{
        It 'Test-IsNotEmpty - $null' {
            Test-IsNotEmpty -field $null | Should Be $true
        }

        It 'Test-IsNotEmpty - empty' {
            Test-IsNotEmpty -field '' | Should Be $true
        }

        It 'Test-IsNotEmpty - test string' {
            Test-IsNotEmpty -field 'test' | Should Be $false
        }

    }#context

    Context 'Test-Is40chars Function'{
        It 'Test-Is40chars - $null' {
            Test-Is40chars -field $null | Should Be $false
        }

        It 'Test-Is40chars - 39 Chars' {
            Test-Is40chars -field '111111111111111111111111111111111111111' | Should Be $false
        }

        It 'Test-Is40chars - 40 Chars' {
            Test-Is40chars -field '1111111111111111111111111111111111111111' | Should Be $true
        }

    }#context

    Context 'Test-HasNoSpaces Function'{
        It 'Test-HasNoSpaces - $null' {
            Test-HasNoSpaces -field $null | Should Be $true
        }

        It 'Test-HasNoSpaces - no spaces' {
            Test-HasNoSpaces -field 'testwithnospaces' | Should Be $true
        }

        It 'Test-HasNoSpaces - spaces' {
            Test-HasNoSpaces -field 'test with spaces' | Should Be $false
        }

    }#context

    $jcAdmuTempPath = 'C:\Windows\Temp\JCADMU\'
    $msvc2013x64File = 'vc_redist.x64.exe'
    $msvc2013x86File = 'vc_redist.x86.exe'
    $msvc2013x86Link = 'http://download.microsoft.com/download/0/5/6/056dcda9-d667-4e27-8001-8a0c6971d6b1/vcredist_x86.exe'
    $msvc2013x64Link = 'http://download.microsoft.com/download/0/5/6/056dcda9-d667-4e27-8001-8a0c6971d6b1/vcredist_x64.exe'
    $msvc2013x86Install = "$jcAdmuTempPath$msvc2013x86File /install /quiet /norestart"
    $msvc2013x64Install = "$jcAdmuTempPath$msvc2013x64File /install /quiet /norestart"
  # JumpCloud Agent Installation Variables
    $AGENT_PATH = "${env:ProgramFiles}\JumpCloud"
    $AGENT_CONF_FILE = "\Plugins\Contrib\jcagent.conf"
    $AGENT_BINARY_NAME = "JumpCloud-agent.exe"
    $AGENT_SERVICE_NAME = "JumpCloud-agent"
    $AGENT_INSTALLER_URL = "https://s3.amazonaws.com/jumpcloud-windows-agent/production/JumpCloudInstaller.exe"
    $AGENT_INSTALLER_PATH = "C:\windows\Temp\JCADMU\JumpCloudInstaller.exe"
    $AGENT_UNINSTALLER_NAME = "unins000.exe"
    $EVENT_LOGGER_KEY_NAME = "hklm:\SYSTEM\CurrentControlSet\services\eventlog\Application\JumpCloud-agent"
    $INSTALLER_BINARY_NAMES = "JumpCloudInstaller.exe,JumpCloudInstaller.tmp"
	$JumpCloudConnectKey = $TestOrgAPIKey
		if ((Test-Path 'C:\Windows\Temp\JCADMU') -eq $true){
                remove-item -Path 'C:\windows\Temp\JCADMU' -Force

            }

				new-item -ItemType Directory -Path 'C:\windows\Temp\JCADMU' -Force 
          # Agent Installer Loop
            [int]$InstallReTryCounter = 0
            Do
            {
                $ConfirmInstall = DownloadAndInstallAgent -msvc2013x64link:($msvc2013x64Link) -msvc2013path:($jcAdmuTempPath) -msvc2013x64file:($msvc2013x64File) -msvc2013x64install:($msvc2013x64Install) -msvc2013x86link:($msvc2013x86Link) -msvc2013x86file:($msvc2013x86File) -msvc2013x86install:($msvc2013x86Install)
                $InstallReTryCounter++
                If ($InstallReTryCounter -eq 3)
                {
                    Write-Log -Message:('JumpCloud agent installation failed') -Level:('Error')
                    Exit;
                }
            } While ($ConfirmInstall -ne $true -and $InstallReTryCounter -le 3)
     

    #uninstall jcagent
    #uninstall c++ 2013 x64
    #uninstall c++ 2013 x86

    Context 'DownloadAndInstallAgent Function'{
        It 'DownloadAndInstallAgent - Verify Download JCAgent prereq Visual C++ 2013 x64' {
            Test-path 'C:\Windows\Temp\JCADMU\vc_redist.x64.exe' | Should Be $true
        }

        It 'DownloadAndInstallAgent - Verify Download JCAgent prereq Visual C++ 2013 x86' {
            Test-path 'C:\Windows\Temp\JCADMU\vc_redist.x86.exe' | Should Be $true
        }

        It 'DownloadAndInstallAgent - Verify Download JCAgent' {
            Test-path 'C:\Windows\Temp\JCADMU\JumpCloudInstaller.exe' | Should Be $true
        }

        It 'DownloadAndInstallAgent - Verify Install JCAgent prereq Visual C++ 2013 x64' {
            (Check_Program_Installed("Microsoft Visual C\+\+ 2013 x64")) | Should Be $true
        }

        It 'DownloadAndInstallAgent - Verify Install JCAgent prereq Visual C++ 2013 x86' {
            (Check_Program_Installed("Microsoft Visual C\+\+ 2013 x86")) | Should Be $true
        }

        It 'DownloadAndInstallAgent - Verify Install JCAgent' {
            (Check_Program_Installed("JumpCloud")) | Should Be $true
        }
    }#context

    Context 'GetNetBiosName Function'{
        It 'GetNetBiosName - JCADB2' {
            GetNetBiosName | Should Be 'JCADB2'
        }

    }#context

    Context 'ConvertSID Function'{
        It 'ConvertSID - Built In Administrator SID' {
            ConvertSID -Sid 'S-1-5-21-1382148263-173757150-4289105529-500' | Should Be '10PRO18091\Administrator'
        }

    }#context

}#describe
