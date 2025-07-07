# 🦀 KryptoWątki-Rust

Platforma badawcza napisana w języku **Rust**, służąca do analizy wydajności algorytmów kryptograficznych (AES, RSA) oraz wielowątkowego przetwarzania tekstu. Projekt umożliwia testowanie i porównywanie czasu wykonania, zużycia CPU oraz pamięci RAM.

---

## 📘 Opis projektu

Główne cele projektu to:

- Ocena wydajności algorytmów szyfrowania i deszyfrowania (AES, RSA),
- Testowanie operacji wielowątkowych na dużych plikach tekstowych,
- Pomiar zasobożerności operacji (czas, CPU, RAM),
- Sprawdzenie możliwości języka Rust w zakresie kryptografii i wielowątkowości.

---

## 🔍 Funkcjonalności

### 🛡 Tryb kryptograficzny:
- Szyfrowanie i deszyfrowanie danych (AES, RSA),
- Możliwość użycia własnych danych lub generacja losowych,
- Konfiguracja: liczba haseł, długość tekstu, długość klucza.

### 🔄 Tryb wielowątkowego przetwarzania tekstu:
- Przeszukiwanie dużych plików tekstowych w wielu wątkach,
- Wybór liczby wątków, słów kluczowych, pliku źródłowego,
- Zwracanie wyników i pomiar wydajności.

### 📊 Pomiar wydajności:
- Czas przetwarzania (real / user / system),
- Zużycie CPU,
- Zużycie pamięci RAM.
