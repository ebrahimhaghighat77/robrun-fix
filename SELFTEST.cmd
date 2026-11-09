@echo off
powershell.exe -NoProfile -Command "Start-Process -FilePath '%~dp0RobRunFix.exe' -ArgumentList '--selftest' -Verb RunAs"
