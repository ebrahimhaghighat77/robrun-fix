@echo off
setlocal
set "root=%~dp0"
set "csc=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%root%dist" mkdir "%root%dist"
"%csc%" -nologo -platform:x64 -main:RobRunFix.Tests -out:"%root%dist\tests.exe" "%root%src\RobRunFix.cs" "%root%tests\FixTests.cs" || exit /b 1
"%root%dist\tests.exe" %*
