#dim Version[4]
#define ApplicationName 'Universal Scanner'
#define ApplicationExe 'UniversalScanner.exe'
#expr ParseVersion("UniversalScanner.exe", Version[0], Version[1], Version[2], Version[3])


[Setup]
AppName={#ApplicationName}
AppVersion={#Version[0]}.{#Version[1]}
VersionInfoVersion={#Version[0]}.{#Version[1]}.{#Version[2]}.{#Version[3]}
VersionInfoCopyright=Julien Blitte
DefaultDirName={commonpf}\{#ApplicationName}
DefaultGroupName={#ApplicationName}
UninstallDisplayIcon={app}\{#ApplicationExe}
Compression=lzma2
SolidCompression=yes
OutputBaseFilename={#ApplicationName} Setup
OutputDir=.

[Files]
Source: "UniversalScanner.exe"; DestDir: "{app}"

[Icons]
Name: "{group}\{#ApplicationName}"; Filename: "{app}\{#ApplicationExe}"
Name: "{group}\Uninstall {#ApplicationName}"; Filename: "{uninstallexe}"
