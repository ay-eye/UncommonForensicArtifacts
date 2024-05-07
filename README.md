# ForensicArtifacts

# Table of Contents
1. [RMM Tools](#RMM-Tools)
    1. [AnyDesk](#AnyDesk)
    2. [ConnectWise (ScreenConnect)](#ConnectWise)
    3. [TeamViewer](#TeamViewer)

------------------------------------

## RMM Tools

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
- TeamViewer Mode (`Remote Control` (Remote Desktop) or `File Transfer` (Only file transfers))`
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