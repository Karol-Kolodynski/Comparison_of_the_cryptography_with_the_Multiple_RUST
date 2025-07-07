// src/rsa_aes.rs
#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use winapi::{
    shared::minwindef::{FILETIME, DWORD},
    um::{
        processthreadsapi::GetProcessTimes,
        psapi::GetProcessMemoryInfo as WinGetProcessMemoryInfo,
        processthreadsapi::GetCurrentProcess,
    },
};
use ctr::cipher::{StreamCipher, KeyIvInit};
use rsa::{RsaPublicKey, RsaPrivateKey, Pkcs1v15Encrypt}; // Dodano Pkcs1v15Encrypt
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rand::{Rng, thread_rng, distributions::Alphanumeric, rngs::StdRng, SeedableRng};
use hex;
use std::time::{Instant, SystemTime};
use std::io;
use std::mem;

const AES_BLOCK_SIZE: usize = 16;

#[repr(C)]
struct PROCESS_MEMORY_COUNTERS {
    cb: DWORD,
    PageFaultCount: DWORD,
    PeakWorkingSetSize: usize,
    WorkingSetSize: usize,
    QuotaPeakPagedPoolUsage: usize,
    QuotaPagedPoolUsage: usize,
    QuotaPeakNonPagedPoolUsage: usize,
    QuotaNonPagedPoolUsage: usize,
    PagefileUsage: usize,
    PeakPagefileUsage: usize,
    PrivateUsage: usize,
}

#[allow(non_snake_case)]
fn EncryptDecryptAES(plaintext: &str, keySize: usize) {
    let mut rng = thread_rng();
    
    let key = match keySize {
        128 | 192 | 256 => {
            let mut key = vec![0u8; keySize / 8];
            rng.fill(&mut key[..]);
            key
        }
        _ => {
            eprintln!("Nieprawidlowy rozmiar klucza AES.");
            return;
        }
    };

    let mut iv = [0u8; AES_BLOCK_SIZE];
    rng.fill(&mut iv[..]);

    println!("Klucz AES (hex):\n{}", hex::encode(&key));
    println!("Tekst oryginalny: {}", plaintext);

    // Wybierz odpowiedni szyfr na podstawie długości klucza
    match key.len() {
        16 => { // AES-128
            use aes::Aes128;
            let mut cipher = ctr::Ctr64LE::<Aes128>::new_from_slices(&key, &iv).unwrap();
            let mut buffer = plaintext.as_bytes().to_vec();
            cipher.apply_keystream(&mut buffer);
            println!("Zaszyfrowany tekst (hex): {}", hex::encode(&buffer));
            
            let mut decipher = ctr::Ctr64LE::<Aes128>::new_from_slices(&key, &iv).unwrap();
            decipher.apply_keystream(&mut buffer);
            println!("Tekst odszyfrowany: {}", String::from_utf8_lossy(&buffer));
        }
        24 => { // AES-192
            use aes::Aes192;
            let mut cipher = ctr::Ctr64LE::<Aes192>::new_from_slices(&key, &iv).unwrap();
            let mut buffer = plaintext.as_bytes().to_vec();
            cipher.apply_keystream(&mut buffer);
            println!("Zaszyfrowany tekst (hex): {}", hex::encode(&buffer));
            
            let mut decipher = ctr::Ctr64LE::<Aes192>::new_from_slices(&key, &iv).unwrap();
            decipher.apply_keystream(&mut buffer);
            println!("Tekst odszyfrowany: {}", String::from_utf8_lossy(&buffer));
        }
        32 => { // AES-256
            use aes::Aes256;
            let mut cipher = ctr::Ctr64LE::<Aes256>::new_from_slices(&key, &iv).unwrap();
            let mut buffer = plaintext.as_bytes().to_vec();
            cipher.apply_keystream(&mut buffer);
            println!("Zaszyfrowany tekst (hex): {}", hex::encode(&buffer));
            
            let mut decipher = ctr::Ctr64LE::<Aes256>::new_from_slices(&key, &iv).unwrap();
            decipher.apply_keystream(&mut buffer);
            println!("Tekst odszyfrowany: {}", String::from_utf8_lossy(&buffer));
        }
        _ => unreachable!(),
    }
    
    println!("IV (hex):\n{}", hex::encode(iv));
}

#[allow(non_snake_case)]
fn EncryptDecryptRSA(plaintext: &str, bits: usize) {
    let mut rng = StdRng::from_entropy();
    let private_key = RsaPrivateKey::new(&mut rng, bits).unwrap();
    let public_key = RsaPublicKey::from(&private_key);

    println!(
        "Prywatny klucz RSA (PEM):\n{}", 
        *private_key.to_pkcs8_pem(LineEnding::LF).unwrap()
    );
    println!(
        "Publiczny klucz RSA (PEM):\n{}", 
        public_key.to_public_key_pem(LineEnding::LF).unwrap()
    );

    // Zmiana z OAEP na PKCS#1 v1.5
    let padding = Pkcs1v15Encrypt;
    let ciphertext = public_key.encrypt(&mut rng, padding, plaintext.as_bytes()).unwrap();
    println!("Zaszyfrowany tekst (hex): {}", hex::encode(&ciphertext));

    // Odpowiednia zmiana dla deszyfrowania
    let decrypted = private_key.decrypt(padding, &ciphertext).unwrap();

    println!("Tekst odszyfrowany: {}", String::from_utf8_lossy(&decrypted));
}


#[allow(non_snake_case)]
fn generateRandomText(min_length: usize, max_length: usize) -> String {
    let len = thread_rng().gen_range(min_length..=max_length);
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

#[allow(non_snake_case)]
fn GetProcessorTimes(userTime: &mut FILETIME, kernelTime: &mut FILETIME) {
    unsafe {
        let mut creationTime = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let mut exitTime = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        GetProcessTimes(
            GetCurrentProcess(),
            &mut creationTime,
            &mut exitTime,
            kernelTime,
            userTime,
        );
    }
}

fn FileTimeToSeconds(ft: &FILETIME) -> f64 {
    ((ft.dwHighDateTime as u64) << 32 | ft.dwLowDateTime as u64) as f64 / 1e7
}

#[allow(non_snake_case)]
fn GetProcessMemoryInfo() -> PROCESS_MEMORY_COUNTERS {
    unsafe {
        let mut pmc: PROCESS_MEMORY_COUNTERS = mem::zeroed();
        pmc.cb = mem::size_of::<PROCESS_MEMORY_COUNTERS>() as DWORD;
        WinGetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut pmc as *mut _ as *mut _,
            pmc.cb,
        );
        pmc
    }
}

#[allow(non_snake_case)]
fn PrintResourceUsage(cpuUsage: f64, pmc: &PROCESS_MEMORY_COUNTERS) {
    println!("Uzycie procesora: {:.2}%", cpuUsage);
    println!("Uzycie pamieci RAM: {} B", pmc.WorkingSetSize);
}

#[allow(non_snake_case)]
pub fn szyfrowanie() {
    let start_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    println!("Wybierz rodzaj szyfrowania: RSA lub AES");
    let mut choice = String::new();
    io::stdin().read_line(&mut choice).unwrap();
    let choice = choice.trim().to_lowercase();

    if choice == "rsa" || choice == "r" {
        let _rng = StdRng::seed_from_u64(start_time);

        println!("Czy chcesz podac wlasny tekst? (T/N)");
        let mut yn = String::new();
        io::stdin().read_line(&mut yn).unwrap();
        let yn = yn.trim().to_lowercase();

        let start = Instant::now();
        let mut userStart = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let mut kernelStart = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        GetProcessorTimes(&mut userStart, &mut kernelStart);
        let _pmcStart = GetProcessMemoryInfo();

        if yn == "t" {
            println!("Podaj tekst:");
            let mut plaintext = String::new();
            io::stdin().read_line(&mut plaintext).unwrap();
            let plaintext = plaintext.trim();

            println!("Podaj dlugosc klucza (512-4096):");
            let mut bytes = String::new();
            io::stdin().read_line(&mut bytes).unwrap();
            let bytes: usize = bytes.trim().parse().unwrap();

            EncryptDecryptRSA(plaintext, bytes);
        } else {
            println!("Podaj ilosc hasel:");
            let mut ilosc = String::new();
            io::stdin().read_line(&mut ilosc).unwrap();
            let ilosc: usize = ilosc.trim().parse().unwrap();

            println!("Podaj dlugosc klucza (512-4096):");
            let mut bytes = String::new();
            io::stdin().read_line(&mut bytes).unwrap();
            let bytes: usize = bytes.trim().parse().unwrap();

            println!("Podaj min dlugosc tekstu:");
            let mut min_len = String::new();
            io::stdin().read_line(&mut min_len).unwrap();
            let min_len: usize = min_len.trim().parse().unwrap();

            println!("Podaj max dlugosc tekstu:");
            let mut max_len = String::new();
            io::stdin().read_line(&mut max_len).unwrap();
            let max_len: usize = max_len.trim().parse().unwrap();

            for _ in 0..ilosc {
                let text = generateRandomText(min_len, max_len);
                EncryptDecryptRSA(&text, bytes);
            }
        }

        let duration = start.elapsed().as_secs_f64();
        let mut userEnd = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let mut kernelEnd = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        GetProcessorTimes(&mut userEnd, &mut kernelEnd);
        let pmcEnd = GetProcessMemoryInfo();

        let userTime = FileTimeToSeconds(&userEnd) - FileTimeToSeconds(&userStart);
        let kernelTime = FileTimeToSeconds(&kernelEnd) - FileTimeToSeconds(&kernelStart);
        let cpuUsage = ((userTime + kernelTime) / duration) * 100.0;

        println!("\n=== Statystyki wydajnosci ===");
        println!("Czas wykonania: {:.2} s", duration);
        PrintResourceUsage(cpuUsage, &pmcEnd);
    } else if choice == "aes" || choice == "a" {
        println!("Czy chcesz podac wlasny tekst? (T/N)");
        let mut yn = String::new();
        io::stdin().read_line(&mut yn).unwrap();
        let yn = yn.trim().to_lowercase();

        let start = Instant::now();
        let mut userStart = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let mut kernelStart = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        GetProcessorTimes(&mut userStart, &mut kernelStart);
        let _pmcStart = GetProcessMemoryInfo();

        if yn == "t" {
            println!("Podaj tekst:");
            let mut plaintext = String::new();
            io::stdin().read_line(&mut plaintext).unwrap();
            let plaintext = plaintext.trim();

            println!("Podaj dlugosc klucza (128 | 192 | 256):");
            let mut bytes = String::new();
            io::stdin().read_line(&mut bytes).unwrap();
            let bytes: usize = bytes.trim().parse().unwrap();

            EncryptDecryptAES(plaintext, bytes);
        } else {
            println!("Podaj ilosc hasel:");
            let mut ilosc = String::new();
            io::stdin().read_line(&mut ilosc).unwrap();
            let ilosc: usize = ilosc.trim().parse().unwrap();

            println!("Podaj dlugosc klucza (128 | 192 | 256):");
            let mut bytes = String::new();
            io::stdin().read_line(&mut bytes).unwrap();
            let bytes: usize = bytes.trim().parse().unwrap();

            println!("Podaj min dlugosc tekstu:");
            let mut min_len = String::new();
            io::stdin().read_line(&mut min_len).unwrap();
            let min_len: usize = min_len.trim().parse().unwrap();

            println!("Podaj max dlugosc tekstu:");
            let mut max_len = String::new();
            io::stdin().read_line(&mut max_len).unwrap();
            let max_len: usize = max_len.trim().parse().unwrap();

            for _ in 0..ilosc {
                let text = generateRandomText(min_len, max_len);
                EncryptDecryptAES(&text, bytes);
            }
        }

        let duration = start.elapsed().as_secs_f64();
        let mut userEnd = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let mut kernelEnd = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        GetProcessorTimes(&mut userEnd, &mut kernelEnd);
        let pmcEnd = GetProcessMemoryInfo();

        let userTime = FileTimeToSeconds(&userEnd) - FileTimeToSeconds(&userStart);
        let kernelTime = FileTimeToSeconds(&kernelEnd) - FileTimeToSeconds(&kernelStart);
        let cpuUsage = ((userTime + kernelTime) / duration) * 100.0;

        println!("\n=== Statystyki wydajnosci ===");
        println!("Czas wykonania: {:.2} s", duration);
        PrintResourceUsage(cpuUsage, &pmcEnd);
    } else {
        println!("Nieprawidlowy wybor szyfrowania!");
    }
}