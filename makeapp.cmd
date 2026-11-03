@echo off
rem Run from the folder containing this file, regardless of the caller's working directory
cd /d "%~dp0"
intunewinapputil.exe -c .\RenameComputer -s RenameComputer.ps1 -o .\ -q
