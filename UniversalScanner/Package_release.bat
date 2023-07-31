@echo off
"%ProgramFiles(x86)%\Inno Setup 6\Compil32.exe" /cc "UniversalScanner.iss"
powershell "Compress-Archive 'UniversalScanner.exe' UniversalScanner.Portable.%date%.zip"
powershell "Compress-Archive 'UniversalScanner Setup.exe' UniversalScanner.Installer.%date%.zip"