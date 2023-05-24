@echo off

cd bin\Release

"%ProgramFiles(x86)%\Inno Setup 6\Compil32.exe" /cc "UniversalScanner.iss"

powershell "Compress-Archive 'UniversalScanner.exe' UniversalScanner.Installer.%date%.zip"

powershell "Compress-Archive 'UniversalScanner Setup.exe' UniversalScanner.Portable.%date%.zip"