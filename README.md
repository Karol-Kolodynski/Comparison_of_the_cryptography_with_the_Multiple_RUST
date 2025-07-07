Opis projektu – wersja Rust
Ten projekt to środowisko testowe stworzone w języku Rust, umożliwiające analizę wydajności:

algorytmów kryptograficznych (AES, RSA),

wielowątkowego przetwarzania tekstu.

Celem jest ocena możliwości języka Rust w kontekście szyfrowania, deszyfrowania oraz operacji na dużych plikach tekstowych z wykorzystaniem wielu wątków. Projekt pozwala na pomiar zużycia zasobów systemowych (czas, CPU, RAM) i daje użytkownikowi elastyczność w konfiguracji testów.

Zakres funkcjonalny
Tryb kryptograficzny:

Szyfrowanie i deszyfrowanie danych przy użyciu AES i RSA,

Obsługa danych wejściowych: tekst własny lub dane losowe,

Ustawienia parametrów: liczba haseł, długość tekstu, długość klucza.

Tryb tekstowy (wielowątkowy):

Przeszukiwanie pliku tekstowego z wykorzystaniem wielu wątków,

Możliwość określenia liczby wątków, słów kluczowych i pliku wejściowego.

Pomiar wydajności:

Czas wykonania,

Zużycie CPU,

Zużycie pamięci RAM.
