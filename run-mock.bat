@echo off
echo Starting Mock Servers...

:: Start Kakao Server (8081)
echo Starting Kakao Server on port 8081...
start cmd /k "cd kakao-server && gradlew bootRun --console=plain"

:: Start SMS Server (8082)
echo Starting SMS Server on port 8082...
start cmd /k "cd sms-server && gradlew bootRun --console=plain"

echo All Mock Servers have been started successfully!
