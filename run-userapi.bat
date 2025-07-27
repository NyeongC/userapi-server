@echo off
echo [User API Test] Start...

cd userapi-server
call gradlew clean test --console=plain

echo Opening test report...
start "" "build\\reports\\tests\\test\\index.html"

pause
