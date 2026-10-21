# Przegląd bezpieczeństwa i poprawności — 2026-10-21

## Zakres i wynik

Przeanalizowano nową obsługę PBKDF2 oraz istniejące `CryptoStrings`, `HashParts`
i testy. PBKDF2 oraz nowy format AES z ochroną integralności mają testy poprawności
i walidacji danych. Nie jest to formalny
audyt ani certyfikacja kryptograficzna. Błędy obsługi certyfikatów i podpisów zostały
naprawione zgodnie z sekcją poniżej. Pozostałe problemy starszych funkcji pozostają
otwarte; dodanie PBKDF2 nie czyni całej biblioteki bezpieczną do wszystkich zastosowań.

## PBKDF2

- Po migracji na `net48;net10.0` usunięto zależność
  `Microsoft.AspNetCore.Cryptography.KeyDerivation` oraz jej zależności przechodnie.
  Dla `net48` używany jest `Rfc2898DeriveBytes`, a dla `net10.0` statyczne
  `Rfc2898DeriveBytes.Pbkdf2`. PRF to jawnie HMAC-SHA-256; bajty ścisłego UTF-8,
  liczba iteracji, podział kluczy i formaty rekordów pozostały takie same.
- Framework odrzuca sole krótsze niż osiem bajtów. Aby zachować kontrakt starego
  niskopoziomowego `HashPbkdf2` (1..64 bajty soli), tylko dla soli 1..7 bajtów
  wariant `net48` używa wbudowanego Windows CNG `BCryptDeriveKeyPBKDF2`. Uchwyt
  dostawcy jest zarządzany przez `SafeHandle`, kod NTSTATUS jest sprawdzany,
  biblioteka jest ładowana wyłącznie z System32, a bufor hasła czyszczony.
  Nie implementowano własnego prymitywu PBKDF2.
- Nowe rekordy mają minimum 600 000 iteracji, losową sól 128-bitową i wynik
  256-bitowy. Jest to zgodne z aktualnym punktem odniesienia
  [OWASP dla PBKDF2](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2).
  OWASP preferuje Argon2id przy swobodnym wyborze algorytmu. Użycie PBKDF2 samo
  w sobie nie oznacza zgodności wdrożenia z FIPS.
- Wersja, PRF i liczba iteracji są zapisane razem z solą i wynikiem. Parser
  sprawdza pełną strukturę, długości, kanoniczne Base64 i liczby. Błędne dane
  nie uruchamiają KDF. Nie ma przełączania na słabszy PRF.
- Limit 160 znaków rekordu, 64 bajtów soli, stałe 32 bajty wyniku oraz sufit
  2 000 000 iteracji ograniczają zużycie zasobów narzucone przez rekord. Sufit to
  lokalna decyzja biblioteki, nie wartość zalecana przez OWASP. Nadal potrzebne
  są limity prób logowania, rozmiaru żądań i współbieżności w aplikacji.
- Weryfikator dopuszcza starszy koszt od 1 iteracji w tym formacie, aby umożliwić
  migrację. `NeedsPbkdf2Rehash` wykrywa taki rekord. Aplikacja musi go zastąpić
  po poprawnym logowaniu. API tworzenia rekordów nie pozwala zejść poniżej
  600 000. Niskopoziomowe `HashPbkdf2` świadomie dopuszcza słabsze parametry
  dla interoperacyjności; nie należy używać ich do nowych haseł.
- Porównywanie tablic nie przerywa się po pierwszej różnicy. `net10.0` korzysta
  z `CryptographicOperations.FixedTimeEquals`, a `net48` zachowuje pętlę chronioną
  przed inliningiem i optymalizacją. Wczesne odrzucenie różnych długości
  dotyczy jawnych parametrów. Zmiana obejmuje też starsze walidatory. Nie wykonano
  pomiarowego audytu kanałów bocznych wszystkich środowisk JIT.
- Hasła używają UTF-8 bez normalizacji i obcinania. Odrzucane są niesparowane
  surogaty, aby kodowanie zastępcze nie utożsamiało różnych haseł. Puste hasła
  i znaki NUL są obsługiwane; polityka siły hasła należy do aplikacji.
- Tymczasowe wyprowadzone klucze są czyszczone w `finally`. Nie można zagwarantować
  wymazania niemodyfikowalnego hasła typu `string` ani wszystkich kopii runtime.

## Nowy format AES z uwierzytelnieniem

- Dodano `$AesAuthenticated$` z binarną wersją `1`, niezależnie od starego `$Aes$`.
  Wersja jednoznacznie określa PBKDF2-HMAC-SHA256, AES-256-CBC/PKCS7 i HMAC-SHA256.
  Użyto wbudowanych prymitywów .NET. Wariant encrypt-then-MAC zapewnia ten sam
  format na obu targetach bez własnej implementacji AES/GCM.
  Jest to wariant opisany w
  [zaleceniach OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#cipher-modes)
  dla platform bez dostępnego trybu uwierzytelnionego.
- Dla każdej operacji losowane są osobno 16-bajtowa sól KDF oraz 16-bajtowy IV.
  PBKDF2 zwraca 64 bajty dzielone na rozłączne klucze AES i HMAC po 32 bajty.
  Domyślny koszt wynosi 600 000 iteracji; dozwolone jest 600 000–2 000 000.
  Ze względu na dwa bloki PBKDF2 koszt jest wyższy niż dla 32-bajtowego weryfikatora
  hasła. Dobór wydajności wymaga pomiaru na docelowej platformie.
- Pełny 32-bajtowy HMAC obejmuje stały identyfikator formatu, wersję, liczbę iteracji,
  sól, IV i cały szyfrogram. Tylko poprawny tag pozwala utworzyć deszyfrator AES.
  Uszkodzone dane nie trafiają do sprawdzania dopełnienia CBC. Porównanie tagów
  używa tej samej funkcji bez przedwczesnego zakończenia co PBKDF2.
- Nieznane wersje, nieprawidłowe długości, niekanoniczne Base64 oraz koszt spoza
  zakresu są odrzucane przed KDF. Maksimum danych wejściowych to 16 MiB. Ograniczono
  też długość kodowanego rekordu przed dekodowaniem, co ogranicza alokacje pamięci.
  Limity nie zastępują limitowania żądań i współbieżnych operacji w aplikacji.
- Materiał KDF i oba klucze są czyszczone w `finally`. Tekst używa ścisłego UTF-8,
  bez normalizacji, ucinania i usuwania NUL. Ograniczenia usuwania `string` z pamięci
  nadal obowiązują. Hasło musi mieć odpowiednią siłę, ponieważ rekord umożliwia
  sprawdzanie hipotez offline.
- `DecryptAesData`/`DecryptAesText` i ogólne `DecryptData`/`DecryptText` odczytują oba
  formaty przez jawny wybór typu. Nie próbują starego formatu po błędzie nowego.
  Czytniki `DecryptAuthenticatedAesData`/`DecryptAuthenticatedAesText` przyjmują
  wyłącznie nowy format; po migracji należy ich używać, aby wymagać uwierzytelnienia.
  Stare metody zapisu pozostają zgodne; nowe zapisy wymagają przejścia na
  `GetAuthenticatedAesCryptoString`. Nie dokonano automatycznej migracji danych.
- Test niezależnego wektora używa osobno wyliczonego `Rfc2898DeriveBytes`, AES i
  HMAC. Utrwalony stary szyfrogram potwierdza odczyt i możliwość ponownego zapisu
  w nowym formacie. Testy modyfikują nagłówek, koszt, sól, IV, szyfrogram i każdy
  bajt tagu; sprawdzają też błędne hasło, odcięcie/dodanie bloków, brak fallbacku,
  pełny zakres bajtów, puste dane, Unicode/NUL, limit 16 MiB i parametry graniczne.

Ten format chroni poufność i integralność, ale nie zapewnia świeżości ani powiązania
rekordu z konkretnym obiektem aplikacji. Ochrona przed replay/rollback i zamianą
całych poprawnych rekordów wymaga sprawdzania kontekstu i wersji danych przez
aplikację. `IsValidCryptoString` weryfikuje składnię, a nie autentyczność tagu.

## Naprawione błędy certyfikatów i podpisów

- `DecryptData` dla `Cert` korzysta teraz ze ścieżki hybrydowej `DecryptCertData`:
  odszyfrowuje RSA klucz z metadanych, a następnie AES-em właściwe dane. Wszystkie
  ścieżki tekstowe korzystają z tej samej obsługi. `DecryptText` akceptuje brak
  hasła tekstowego przy operacjach z kluczem RSA.
- `VerifySign(string, X509Certificate2)` deleguje do weryfikatora RSA, który wymaga
  typu `Sign`. `GetSignData` pobiera publiczny klucz certyfikatu. `GetSignText`
  korzysta z tego samego kodu weryfikacji i ekstrakcji. Certyfikat publiczny
  wystarcza do wszystkich operacji weryfikacji.
- `DecryptData`/`DecryptText` dla `Sign` wymagają teraz zaufanego klucza RSA i nie
  zwracają danych bez poprawnego podpisu. Jest to celowa zmiana zachowania API,
  bez zmiany zapisanych danych. Dotychczasowy parametr `privateKey` zachował nazwę,
  ale dla `Sign` wystarczy jego publiczna część. Jawna ekstrakcja bez weryfikacji
  jest nadal dostępna przez `GetHashParts(...).Hash`.
- Uporządkowano błędy brakujących kluczy i metadanych. Tymczasowy klucz odszyfrowany
  z rekordu `Cert` jest czyszczony po użyciu. Nie zwalnia się obiektów RSA przekazanych
  przez wywołującego; zwalniane są klucze pobrane wewnętrznie z certyfikatów.
- `DecryptTextTest` osobno sprawdza dane binarne i tekst UTF-8, bez błędnego
  porównania `string` z `byte[]`.
- Zachowano formaty, algorytmy, dopełnienia i interpretację istniejących metadanych,
  w tym 32-bajtowe pole soli `Cert` i pusty opcjonalny thumbprint. Testy odczytują
  utrwalone rekordy utworzone przed poprawką; nowy podpis musi być identyczny
  bajtowo ze starym, a nowy szyfrogram jest odczytywany niezależną implementacją
  starej sekwencji RSA-OAEP-SHA1 / AES-CBC.

Wywołujący nadal odpowiada za zaufanie do klucza/certyfikatu. Kod nie sprawdza
łańcucha zaufania, ważności ani unieważnienia certyfikatu. Pole thumbprint jest
metadanymi nieobjętymi podpisem, a nie dowodem tożsamości. Utrzymanie zgodności
szyfrogramów nie dodaje im uwierzytelnienia.

## Otwarte problemy starszego kodu

| Priorytet | Miejsce | Ustalenie i skutek | Zalecenie |
| --- | --- | --- | --- |
| Wysoki dla starego formatu | `CryptoStrings.EncryptAes` / `DecryptAes` | Hasło jest kopiowane bezpośrednio do klucza, obcinane do jego długości albo dopełniane zerami. Nie ma kosztownej funkcji KDF ani soli KDF; hasła o tym samym dostatecznie długim prefiksie dają ten sam klucz. | Nowe dane zapisywać przez `GetAuthenticatedAesCryptoString`, stare migrować po poprawnym odczycie. Interpretacja starego formatu pozostaje bez zmian. |
| Wysoki dla starych formatów | Stary `$Aes$` i hybrydowy format `Cert` | Szyfrowanie AES korzysta z domyślnego CBC/PKCS7, bez MAC/tagu. Zmiany szyfrogramu nie są uwierzytelniane; ujawnianie różnic błędów może umożliwić padding oracle. Parametr nazwany `salt` jest IV i przy jawnej wartości może być krótki lub powtarzany. | Migrować `$Aes$` do nowego encrypt-then-MAC. Zmiana hybrydowego `Cert` wymaga osobnego, uwierzytelnionego formatu. Stary odczyt nie potwierdza integralności historycznych danych. |
| Wysoki przy użyciu do haseł | `GetMd5*`, `GetSha*`, `GetNoneCryptoString` | Szybkie hashe, nawet solone, pozwalają na szybkie zgadywanie haseł offline; `None`/`NoneData` nie chronią hasła. | Nowe hasła zapisywać przez PBKDF2; stare migrować po poprawnym logowaniu. Zwykłe SHA-2 nadal mają zastosowania poza przechowywaniem haseł. |
| Średni, zależny od użycia | `HashParts.IsValidHash`, starsze formaty | `Enum.TryParse` akceptuje niezdefiniowane liczby, a sprawdzenie Base64 nie waliduje metadanych, soli ani podpisu. Wynik `true` nie oznacza poprawnego rekordu kryptograficznego. | Walidować zdefiniowany typ i kompletny schemat każdego formatu; oddzielić poprawność składni od uwierzytelnienia. Nowy format PBKDF2 ma pełną walidację składni. |

Nowy format nie dodaje integralności do już istniejących rekordów. Migracja wymaga
odczytu i ponownego szyfrowania; wzorzec dla AES podano w README. Stare rekordy
mogły zostać zmienione przed migracją, czego samo odszyfrowanie nie wykryje.

## Weryfikacja

- Kompilacja Release biblioteki i testów: bez błędów i ostrzeżeń.
- Po przejściu na `net48;net10.0`: pełny zestaw **81/81 na net10.0**.
  Po dostosowaniu ładowania certyfikatów ponownie przeszło **28/28 na każdym
  targecie** (certyfikaty, podpisy, podstawowe operacje oraz wektory RFC PBKDF2).
  Na .NET 10 testy używają `X509CertificateLoader` z rozróżnieniem X.509 i PKCS#12;
  na .NET Framework zachowują dotychczasowe konstruktory. Pełnego zestawu net48
  nie powtarzano w tej migracji; kod kryptograficzny biblioteki nie został zmieniony.
- Przed zmianą nowoczesnego targetu na .NET 10 pełny zestaw przeszedł: **81/81 dla net48**
  oraz **81/81 dla net8.0**. Lokalny czas wyniósł odpowiednio 7 min 55 s i około
  30 s; nie jest to izolowany benchmark samych prymitywów. Testy wzorcowe RFC
  sprawdzają też wariant CNG z ograniczeniem ładowania biblioteki do System32.
- Przed migracją targetów, po dodaniu uwierzytelnionego AES: 81/81 testów
  przechodziło, w tym 24/24 nowych przypadków AES.
- Testy PBKDF2: 31/31. Obejmują dwa wektory z
  [RFC 7914, sekcja 11](https://www.rfc-editor.org/rfc/rfc7914.html#section-11)
  (pierwsze 32 bajty), niezależne wyniki `Rfc2898DeriveBytes` dla UTF-8/NUL/pustego
  i długiego hasła, parametry graniczne, losowe sole, kulturę `ar-SA`, odrzucanie
  błędnych rekordów i modyfikacji każdego bajtu wyniku oraz zgodność starych haseł.
- Przed zmianą pełny zestaw miał 6 sukcesów i 1 błąd (`DecryptTextTest`). Po dodaniu
  PBKDF2 miał 37 sukcesów i ten sam 1 błąd. Po naprawie certyfikatów, podpisów
  i asercji oraz dodaniu 19 przypadków testowych zestaw na tym etapie przeszedł: 57/57.
  Nowe przypadki obejmują też błędny klucz, podmienione dane i podpis, brak klucza,
  błędny typ/strukturę rekordu, tekst UTF-8/NUL, puste dane i własność obiektów RSA.
- `dotnet list src/Vespertan.Cryptography.sln package --vulnerable --include-transitive`:
  brak zgłoszonych podatnych pakietów według dostępnych źródeł w dniu przeglądu.
  Nie jest to gwarancja braku nieznanych podatności.
- Testy jednostkowe są teraz kompilowane i uruchamiane dla `net48` oraz `net10.0`.
  Dodano `tests/Test-CrossTargetCompatibility.ps1`, który uruchamia osobne procesy
  obu targetów i wymienia 39 świeżych rekordów w każdym kierunku. Obejmuje to
  również sole 1..16 bajtów, puste hasła, dane binarne/tekstowe, stare AES,
  certyfikaty i podpisy. Weryfikator odrzuca plik pochodzący z własnego targetu.
  Wymiana przeszła w obu kierunkach: 39/39 rekordów na kierunek, wraz z odrzuceniem
  błędnego hasła i podmienionego tagu.
- Sprawdzono paczkę NuGet: zawiera `lib/net48` i `lib/net10.0`, bez zależności
  pakietowych dla obu targetów. Nie zmieniono wersji schematów zapisanych danych.
- Implementacja zarządzana PBKDF2 w Frameworku może być znacząco wolniejsza niż
  wcześniejszy dostawca CNG. Należy zmierzyć opóźnienia dla produkcyjnego obciążenia.
  Pojedynczy pomiar lokalny `net48`, 600 000 iteracji, sól 16 bajtów i wynik
  32 bajty: około 2,4 s (podczas trwających testów). To obserwacja wydajności,
  nie benchmark gwarantujący czas na innych maszynach.
- Weryfikacja lokalna odbywa się na Windows. Nie wykonano przebiegu na Linux/macOS.
