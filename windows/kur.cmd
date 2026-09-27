@ECHO OFF
cd /d "%~dp0"
net session >nul 2>&1
if errorlevel 1 (
    echo Yonetici olarak calistirin: sag tik, Yonetici olarak calistir.
    pause
    exit /b 1
)
if not exist "%~dp0discorddpi.exe" (
    echo discorddpi.exe bu klasorde yok.
    pause
    exit /b 1
)
if not exist "%~dp0WinDivert.dll" (
    echo WinDivert.dll bu klasorde yok.
    pause
    exit /b 1
)
if not exist "%~dp0WinDivert64.sys" (
    echo WinDivert64.sys bu klasorde yok.
    pause
    exit /b 1
)
sc stop DiscordDPI >nul 2>&1
sc delete DiscordDPI >nul 2>&1
sc create DiscordDPI binPath= "\"%~dp0discorddpi.exe\"" start= auto DisplayName= "DiscordDPI"
if errorlevel 1 (
    echo Hizmet olusturulamadi.
    pause
    exit /b 1
)
sc description DiscordDPI "Yalnizca Discord el sikismasini ve Discord DNS sorgusunu isler." >nul
sc failure DiscordDPI reset= 86400 actions= restart/5000/restart/30000/restart/60000 >nul
sc start DiscordDPI
if errorlevel 1 (
    echo Hizmet baslamadi, kayit silindi.
    sc delete DiscordDPI >nul 2>&1
    pause
    exit /b 1
)
echo.
echo Kuruldu. Windows her acilisinda kendiliginden baslar.
echo Kaldirmak icin kaldir.cmd
echo.
pause
