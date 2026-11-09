@echo off
setlocal
set "root=%~dp0"
set "csc=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
set "out=%root%dist\RobRunFix"
if exist "%root%dist" rmdir /s /q "%root%dist"
mkdir "%out%"
"%csc%" -nologo -platform:x64 -optimize -win32manifest:"%root%src\app.manifest" -out:"%out%\RobRunFix.exe" "%root%src\RobRunFix.cs" || goto :fail
copy /y "%root%vendor\wintun\wintun.dll" "%out%\" >nul
copy /y "%root%vendor\wintun\LICENSE.txt" "%out%\WINTUN-LICENSE.txt" >nul
copy /y "%root%SELFTEST.cmd" "%out%\" >nul
copy /y "%root%README.md" "%out%\" >nul
copy /y "%root%LICENSE" "%out%\" >nul
powershell.exe -NoProfile -Command "[AppContext]::SetSwitch('Switch.System.IO.Compression.ZipFile.UseBackslash', $false); Add-Type -AssemblyName System.IO.Compression.FileSystem; [IO.Compression.ZipFile]::CreateFromDirectory('%out%', '%root%dist\RobRunFix.zip', 'Optimal', $true)" || goto :fail
echo Built %root%dist\RobRunFix.zip
exit /b 0
:fail
echo Build failed.
pause
exit /b 1
