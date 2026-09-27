@ECHO OFF
net session >nul 2>&1
if errorlevel 1 (
    echo Yonetici olarak calistirin: sag tik, Yonetici olarak calistir.
    pause
    exit /b 1
)
sc stop DiscordDPI
sc delete DiscordDPI
echo.
echo Kaldirildi.
echo.
pause
