@rem Oczekiwane jest ze przed wykonanie tego pliku 
@rem zostana ustawione wczesniej zmienne: projekt, katalog, build
@rem projekt to nazwa projektu. Np. ProjektA
@rem katalog to miejsce polozenia projektu wzgledem tego pliku. Np. ..\projekt\
@rem Najlepszym sposobem jest w innym pliku bat zdefioniowac te zmienne,
@rem a nastepnie wywoˆac ten plik.

@rem Zawarto˜c takiego pliku moze wygladac nastepujaco:
@rem @set projekt=Vespertan.DataBase
@rem @set katalog=..\Vespertan.DataBase\
@rem @set apiKey=%VespertanApiKey%
@rem @set build=-Build
@rem @_NUGET_BASE.bat

@echo off
set wersja=
set push=T
set del=T

if exist bin\%projekt%.nupkg del %projekt%.nupkg
dotnet pack %katalog%%projekt%.csproj --configuration Release -o bin
if %errorlevel% NEQ 0 goto  err 

move bin\%projekt%*.nupkg bin\%projekt%.nupkg

echo.
set /P push=Czy wypchnac na serwer? (T/N)[%push%]
if /I [%push%] == [t] (nuget push bin\%projekt%.nupkg %apiKey% -Source %src%)

echo.
set /P del=Usun plik paczki %projekt%.nupkg? (T/N)[%del%]
if /I [%del%] == [t] (del bin\%projekt%.nupkg)
:err
pause