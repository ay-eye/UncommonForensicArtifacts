# Uncommon Forensic Artifacts

# Table of Contents
1. [Remote Access](#Remote-Access)
    1. [AnyDesk](#AnyDesk)
    2. [ConnectWise (ScreenConnect)](#ConnectWise)
    3. [TeamViewer](#TeamViewer)
    4. [ScreenConnect](#ScreenConnect)
    5. [Quick Assist](#Quick-Assist)
    6. [CloudflareD](#CloudflareD)


------------------------------------

## Remote Access

### AnyDesk
Three execution modes: 
1. Installed
2. Portable
3. Portable with elevation

Portal execution relies on a signature DLL: `GCAPI.DLL`
  
##### Installed
###### Logs
```
%PROGRAMDATA%\AnyDesk\
    %PROGRAMDATA%\AnyDesk\connection_trace.txt
    %PROGRAMDATA%\AnyDesk\ad_svc.trace
%APPDATA%\AnyDesk
    %APPDATA%\AnyDesk\ad.trace
    %APPDATA%\AnyDesk\thumbnails\
%USERPROFILE%\Pictures
%USERPROFILE%\Videos
```

`%PROGRAMDATA%\AnyDesk\connection_trace.txt`
- Logs incoming connections
    - Timestamps
    - Connection Status (User, Rejected, Passwd, Token)
    - Request origin

`%PROGRAMDATA%\AnyDesk\ad_svc.trace`
- Contains generic data, but more verbose than ad.trace
    - Errors
    - Connection events
    - System notifications
    - Incoming/Outgoing IPs
    - Downloaded/Uploaded files
    - PIDs
- Does not exist for portable version

`%APPDATA%\AnyDesk\ad.trace`
- Contains generic data
    - Errors
    - Connection events
    - System notifications
- Portable version contains more verbose logging

`%APPDATA%\AnyDesk\thumbnails\`
- Background image of the remote (conencting) system saved here

`%USERPROFILE%\Pictures`
- Screenshots saved here

`%USERPROFILE%\Videos`
- Screen recordings saved here
- Playable within AnyDesk

##### Portable 
###### Logs
```
%APPDATA%\AnyDesk
%USERPROFILE%\Pictures
%USERPROFILE%\Videos
```

`%APPDATA%\AnyDesk\ad.trace`
- Contains generic data
    - Errors
    - Connection events
    - System notifications
- Portable version contains more verbose logging

`%APPDATA%\AnyDesk\thumbnails\`
- Background image of the remote (conencting) system saved here

`%USERPROFILE%\Pictures`
- Screenshots saved here

`%USERPROFILE%\Videos`
- Screen recordings saved here
- Playable within AnyDesk

#### Resources
- https://youtu.be/nZUd50Z83zk?t=735


------------------------------------

### ConnectWise
Two flavors: 
1. On-premise
2. Cloud-based (14-day trial, no credit card)

#### Logs
```
%SYSTEMROOT%\Temp\ScreenConnect\<version>
%PROGRAMDATA%\ScreenConnect Client (<fingerprint string>)
    %PROGRAMDATA%\ScreenConnect Client (<fingerprint string>)\user.config
%PROGRAMFILES(X86)%\ScreenConnect Client (<fingerprint string>)
    %PROGRAMFILES(X86)%\ScreenConnect Client (<fingerprint string>)\app.config
%USERPROFILE%\Documents\ConnectWiseControl\Files
%USERPROFILE%\Documents\ConnectWiseControl\captures
System Windows Event Logs
Application Windows Event Logs
PowerShell Windows Event Logs
C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline
```

`%PROGRAMDATA%\ScreenConnect Client (<fingerprint string>)\user.config`
- Not much forensic value
- Only known forensic value is that it logs the last directory used for file transfer

`%PROGRAMFILES(X86)%\ScreenConnect Client (<fingerprint string>)\app.config`
- Allows for customization of ScreenConnect Client 
    - Can disable banners or other signs of remote access

`Security Windows Event Logs`
- EID 4688 
    - Process Creation
    - Spawned `cmd.exe` or `powershell.exe` from `ScreenConnect.ClientService.exe`
    - Commands containing `run.cmd` or `run.ps1`.

`System Windows Event Logs`
- EID 7045 
    - Service Installation

`Application Windows Event Logs`
- EID 0 
    - Start of remote session
    - Close of remote session
    - File upload/transfer
    - Command exceution
        - Executed as SYSTEM
        - Command exceuted via temprorary Command and PowerShell scripts temmporarily written to and deleted from `%SYSTEMROOT%\Temp`
        - Exact commands exceuted are not logged -- only the length of the command is logged.
        - Known built-in static PowerShell scripts (`run.ps1`) that can be executed via console:
            - `Processes` (command length: 657)
            - `Software` (command length: 861)
            - `Event Log` (command length: 492)
            - `Services` (command length: 460)
            - `Updates` (command length: 725)
        - Manual/custom commands (not built-in) are executed as command (`run.cmd`) scripts (not PowerShell)
- EID 1033, EID 11707
    - MSI application installation

#### Resources
- https://youtu.be/nZUd50Z83zk?t=1525
 

------------------------------------

### TeamViewer

#### Logs
```
C:\Program Files\TeamViewer
    C:\Program Files\TeamViewer\Connections_incoming.txt
C:\Users\<user>\AppData\Roaming\TeamViewer
    C:\Users\<user>\AppData\Roaming\TeamViewer\Connections.txt
    C:\Users\<user>\AppData\Roaming\TeamViewer\MRU\RemoteSupport\.tvc
C:\Program Files\TeamViewer
    C:\Program Files\TeamViewer\TeamViewer<version>_Logfile.log
```

`C:\Program Files\TeamViewer\Connections_incoming.txt`
- Connected TeamViewer ID
- Date and time the connection started
- TeamViewer Mode (`Remote Control` (Remote Desktop) or `File Transfer` (Only file transfers))
- Date and time the connection ended
- Connected device name
- Connected user name
- Connection type
- Connection unique ID

`C:\Users\<user>\AppData\Roaming\TeamViewer\Connections.txt`
- Records outgoing connection details
- Connected TeamViewer ID
- Date and time the connection started
- Date and time the connection ended
- Connected user name
- Connection type

`C:\Program Files\TeamViewer\TeamViewer<version>_Logfile.log`
- Lots of useful information
- Last archived file name
- Connected device information: IP, OS, TeamViewer ID
- Incoming connection
- Outgoing connectiokn
- Denied connection (Wrong password)
- Search the following terms:
    - `AuthenticationPasswordLogin_Passive` that are `successful`
    - `AuthenticationPasswordLogin_Passive` that are `denied`
    - `Trying connection to`
    
`C:\Users\<user>\AppData\Roaming\TeamViewer\MRU\RemoteSupport\.tvc`
- Records outgoing connection TeamViewer IDs

#### Resources
- https://forensafe.com/blogs/teamviewer.html
- https://medium.com/mii-cybersec/digital-forensic-artifact-of-teamviewer-application-cfd6290dc0a7
- https://www.systoolsgroup.com/forensics/teamviewer/

------------------------------------

### ScreenConnect

#### Logs
```
System Windows Event Logs
Application Windows Event Logs
Powershell Windows Event Logs
```

`System Windows Event Logs`
- EID 7045
    - Installation of ScreenConnect service

`Application Windows Event Logs`
- EID 0
    - Start of remote session
    - Closing of remote sessions
    - File upload/transfer (contains a list of files transferred)
    - Command execution (only lists length of command)
        - Manually-executed shell commands are executed via `.cmd` scripts ("`"cmd.exe" /c "C:\Windows\TEMP\ScreenConnect\<version>\<uuid>run.cmd`"")
        - Tasks are executed via `.ps1` scripts

#### Resources
- https://www.huntandhackett.com/blog/revil-the-usage-of-legitimate-remote-admin-tooling

------------------------------------

### Quick Assist

Main executable is within: `C:\Windows\System32\quickassist.exe`

#### NBIs
```
relayv2.support.services.microsoft[.]com
rdprelaynortheuropeprd.cloudapp[.]net (regional)
```

#### Logs
```
RDP Event Logs
RDP Bitmapcahce
SRUM: C:\System32\sru\SRUDB.dat
%LOCALAPPDATA%\Temp\QuickAssist\EBWebView\Default\history
%LOCALAPPDATA%\Temp\QuickAssist\EBWebView\Default\Secure Preferences
%LOCALAPPDATA%\Temp\QuickAssist\EBWebView\Default\Network Action Predictor
%LOCALAPPDATA%\Temp\QuickAssist\EBWebView\Default\Network\DIPS
%LOCALAPPDATA%\Temp\QuickAssist\EBWebView\Default\Session Storage\\d+.txt (e.g. txt file with random numbers)
```

`RDP Artifacts`
- Quick Assist process uses RDP for remote connections

`C:\System32\sru\SRUDB.dat`
- Connections from the quickassist process over the last 60 days

`%LOCALAPPDATA%\Temp\QuickAssist\EBWebView\Default\history`
- Unencrypted
- Tracks historic sessions
- Chromium SQLite database
- Records URLs/network info during the sessions
    - `https://remoteassistance.support.services.microsoft[.]com/screenshare`
        - tracks number of remote sessions
        - timestamp is for the most recent session
    - `https://remoteassistance.support.services.microsoft[.]com/status/ended`
        - timestamp is for the end of the most recent session

    - `https://remoteassistance.support.services.microsoft[.]com/roleselection#` 
        - NOT plain /roleselection (i.e. no #)
        - NOT /roleselection#argument*. 
        - Keeps track of when the client (conencting asset) was given control. Timestamp is for the most recent time of control grant.

`%LOCALAPPDATA%\Temp\QuickAssist\EBWebView\Default\Secure Preferences`
- Created upon first session, not upon installation.
- Creation date is indicative of the timestamp of the first session.


`%LOCALAPPDATA%\Temp\QuickAssist\EBWebView\Default\Session Storage`. 
- A .txt file with a bunch of random numbers in this directory contains: 
    - The domain resolved during creation of the session.
    - List of session creation timestamps.

`%LOCALAPPDATA%\Temp\QuickAssist\EBWebView\Default\Network Action Predictor` 
- Metadata for this dir is modified upon creation of a session.
    - Modified timestamp is indicative of the beginning of the most recent session.

`%LOCALAPPDATA%\Temp\QuickAssist\EBWebView\Default\Network\DIPS` 
- Metadata for this dir is modified upon session activies (i.e. sessions creation, session termination, control grants, etc.)
    - Modified timestamp is indicative of the end of the most recent screenshare session.

#### Resources
- https://www.johncysa.com/forensics-quick-assist
- https://hackuponthegale.github.io/blog/dfir/QuickAssist1
- https://learn.microsoft.com/en-us/windows/client-management/client-tools/quick-assist

------------------------------------

### Cloudflared

Establishes a tunnel through CLoudflare that allows for external entities to directly access services such as SMB, RDP, and SSH.

#### Logs
```
Cmdline arguments including: "tunnel", "run", "--token"
DNS: .*argotunnel[.]com
Firewall: destination port of 7844
Firewall and AV logs will also likely show a handful of Cloudflared IPs utilized by the tunnel
```
#### Resources
- https://www.guidepointsecurity.com/blog/tunnel-vision-cloudflared-abused-in-the-wild/
