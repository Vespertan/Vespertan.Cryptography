:: Version 1.10.0

@echo off

:: Set default project name
if defined projectName goto skipDefaultProjectName
for /f "delims=" %%i in ('dir /b *.csproj 2^>nul') do (set "projectName=%%i" & goto :breakProjectName)
:breakProjectName
set "projectName=%projectName:~0,-7%"
:skipDefaultProjectName

:: Define default value for variables
if not defined projectDir set "projectDir=."
if not defined useDefaultPrompt set useDefaultPrompt=Yes
if not defined deletePackageAfterPush set deletePackageAfterPush=Yes

if not defined localNugetSrc_Dir set localNugetSrc_Dir=
if not defined localNugetSrc_AllowPush set localNugetSrc_AllowPush=Yes

if not defined nugetSrc_AllowPush set nugetSrc_AllowPush=Yes
if not defined nugetSrc_Uri set nugetSrc_Uri=
if not defined nugetSrc_ApiKey set nugetSrc_ApiKey=

if not defined nugetSrc2_AllowPush set nugetSrc2_AllowPush=Yes
if not defined nugetSrc2_Uri set nugetSrc2_Uri=
if not defined nugetSrc2_ApiKey set nugetSrc2_ApiKey=

if not defined incrementProjectVersion_Allow set incrementProjectVersion=No
if not defined incrementProjectVersion_Part set incrementProjectVersion_Part=2


:: Validate variables
if [%nugetSrc_Uri%%nugetSrc2_Uri%%localNugetSrc_Dir%] == [] (echo Error: no nuget source defined. Set at least one variable: nugetSrc_Uri, nugetSrc2_Uri, localNugetSrc_Dir. You can set this variables in file PushProjectToNuget.cmd & goto err)

:: Clean old packages if exists
if exist "%projectDir%\bin\%projectName%*.nupkg" del "%projectDir%\bin\%projectName%*.nupkg"
if exist "%projectDir%\bin\%projectName%*.nupkg" goto err 

:: Increment project version before build
for /f "delims=" %%i in ('where powershell') do set powershellLocation=%%i
if /I [%incrementProjectVersion_Allow:~0,1%] == [y] if not defined powershellLocation (echo "Error: missing powershell. Install PowerShell for increment project version" & goto err)
if /I NOT [%incrementProjectVersion_Allow:~0,1%] == [y] (goto skipIncrementProjectVersion)
set "startVersionRegEx=(?^<=^<Version^>"
set "endVersionRegEx=(?=[\d\w-.]*^</Version^>)"
set psCommand=^
$content = Get-Content '%projectDir%\%projectName%.csproj' -Raw; ^
    if (%incrementProjectVersion_Part% -eq 1) {$content = [regex]::Replace($content, '%startVersionRegEx%)(\d+)%endVersionRegEx%', {param($match) [int]$match.Value + 1}) }; ^
    if (%incrementProjectVersion_Part% -eq 2) {$content = [regex]::Replace($content, '%startVersionRegEx%\d+\.)(\d+)%endVersionRegEx%', {param($match) [int]$match.Value + 1}) }; ^
    if (%incrementProjectVersion_Part% -eq 3) {$content = [regex]::Replace($content, '%startVersionRegEx%\d+\.\d+\.)(\d+)%endVersionRegEx%', {param($match) [int]$match.Value + 1}) }; ^
    if (%incrementProjectVersion_Part% -eq 4) {$content = [regex]::Replace($content, '%startVersionRegEx%\d+\.\d+\.\d+\.)(\d+)%endVersionRegEx%', {param($match) [int]$match.Value + 1}) }; ^
    Set-Content -Path '%projectDir%\%projectName%.csproj' -Value $content -NoNewline;
powershell -Command "%psCommand%"
:skipIncrementProjectVersion

:: Compile package
dotnet pack "%projectDir%\%projectName%.csproj" --configuration Release -o "%projectDir%\bin"
if %errorlevel% NEQ 0 goto err 

:: Set unified package file name
move "%projectDir%\bin\%projectName%*.nupkg" "%projectDir%\bin\%projectName%.nupkg"

:: Push to local feed
if /I NOT [%useDefaultPrompt:~0,1%] == [y] if NOT "%localNugetSrc_Dir%" == "" (set /P localNugetSrc_AllowPush="Push to local feed? (Yes/No)[%localNugetSrc_AllowPush%]")
if NOT [%localNugetSrc_Dir%] == [] (if /I [%localNugetSrc_AllowPush:~0,1%] == [y] (nuget add "%projectDir%\bin\%projectName%.nupkg" -Source "%localNugetSrc_Dir%"))
if %errorlevel% NEQ 0 goto err

:: Push to nuger server 1
if /I NOT [%useDefaultPrompt:~0,1%] == [y] if NOT "%nugetSrc_Uri%" == "" (set /P nugetSrc_AllowPush="Push to %nugetSrc_Uri%? (Yes/No)[%nugetSrc_AllowPush%]")
if NOT [%nugetSrc_Uri%] == [] (if /I [%nugetSrc_AllowPush:~0,1%] == [y] (nuget push "%projectDir%\bin\%projectName%.nupkg" "%nugetSrc_ApiKey%" -Source "%nugetSrc_Uri%"))
if %errorlevel% NEQ 0 goto err

:: Push to nuger server 2
if /I NOT [%useDefaultPrompt:~0,1%] == [y] if NOT "%nugetSrc2_Uri%" == "" (set /P nugetSrc2_AllowPush="Push to %nugetSrc2_Uri%? (Yes/No)[%nugetSrc2_AllowPush%]")
if NOT [%nugetSrc2_Uri%] == [] (if /I [%nugetSrc2_AllowPush:~0,1%] == [y] (nuget push "%projectDir%\bin\%projectName%.nupkg" "%nugetSrc2_ApiKey%" -Source "%nugetSrc2_Uri%"))
if %errorlevel% NEQ 0 goto err

:: Delete compiled package
if /I NOT [%useDefaultPrompt:~0,1%] == [y] set /P deletePackageAfterPush=Delete package file %projectName%.nupkg? (Yes/No)[%deletePackageAfterPush%]
if /I [%deletePackageAfterPush:~0,1%] == [y] (del "%projectDir%\bin\%projectName%.nupkg")
if %errorlevel% NEQ 0 goto err
echo Success!
goto end

:err
echo Error!
pause
:end
