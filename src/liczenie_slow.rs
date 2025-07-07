use std::{
    io::{self},
    time::Instant,
    sync::{Arc, Mutex},
    mem,
};
use winapi::{
    shared::minwindef::FILETIME,
    um::{
        processthreadsapi::{GetCurrentProcess, GetProcessTimes},
        psapi::GetProcessMemoryInfo,
        sysinfoapi::GetSystemInfo,
    },
};
use rayon::prelude::*;

// Stałe
const ROZMIAR_FRAGMENTU: usize = 2 * 1024 * 1024; // 2MB
const OVERLAP_SIZE: usize = 256;

// Struktury
#[allow(non_snake_case)]
#[derive(Debug)]
struct KmpPreprocessed {
    lps: Vec<usize>,
    pattern: String,
}

#[derive(Default, Clone)]
struct Metrics {
    count: i32,
    czas: f64,
    cpu_usage: f64,
    ram_usage: usize,
}

// Windows API wrappers
fn get_cpu_time() -> f64 {
    unsafe {
        let mut create_time = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut exit_time = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut kernel_time = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut user_time = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        
        let process = GetCurrentProcess();
        GetProcessTimes(
            process,
            &mut create_time,
            &mut exit_time,
            &mut kernel_time,
            &mut user_time,
        );

        let user = (user_time.dwHighDateTime as u64) << 32 | user_time.dwLowDateTime as u64;
        let kernel = (kernel_time.dwHighDateTime as u64) << 32 | kernel_time.dwLowDateTime as u64;
        
        (user + kernel) as f64 * 1e-7
    }
}

fn get_memory_usage() -> usize {
    
    #[allow(non_snake_case)]
    #[repr(C)]
    struct PROCESS_MEMORY_COUNTERS_EX {

        cb: u32,
        PageFaultCount: u32,
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

    unsafe {
        let mut pmc: PROCESS_MEMORY_COUNTERS_EX = mem::zeroed();
        pmc.cb = mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
        
        let process = GetCurrentProcess();
        GetProcessMemoryInfo(
            process,
            &mut pmc as *mut _ as *mut _,
            mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
        );
        
        pmc.PrivateUsage
    }
}

// Funkcje pomocnicze
fn odczytaj_caly_plik(sciezka: &str) -> io::Result<Vec<u8>> {
    std::fs::read(sciezka)
}

fn podziel_na_fragmenty(buffer: &[u8]) -> Vec<(usize, usize)> {
    let mut fragmenty = Vec::new();
    let mut poz = 0;
    
    while poz < buffer.len() {
        let start = poz.saturating_sub(OVERLAP_SIZE);
        let end = (poz + ROZMIAR_FRAGMENTU).min(buffer.len());
        fragmenty.push((start, end));
        poz = end;
    }
    
    fragmenty
}

// Implementacja KMP
fn przygotuj_wzorzec(slowo: &str) -> KmpPreprocessed {
    let pattern = slowo.as_bytes();
    let mut lps = vec![0; slowo.len()];
    let mut len = 0;

    for i in 1..pattern.len() {
        while len > 0 && pattern[i] != pattern[len] {
            len = lps[len - 1];
        }
        
        if pattern[i] == pattern[len] {
            len += 1;
            lps[i] = len;
        }
    }

    KmpPreprocessed {
        lps,
        pattern: slowo.to_string(),
    }
}

fn liczba_slow_we_fragmencie(fragment: &[u8], wzorzec: &KmpPreprocessed) -> i32 {
    let pattern = wzorzec.pattern.as_bytes();
    let mut count = 0;
    let (mut i, mut j) = (0, 0);

    while i < fragment.len() {
        if fragment[i] == pattern[j] {
            i += 1;
            j += 1;
        }

        if j == pattern.len() {
            count += 1;
            j = wzorzec.lps[j - 1];
        } else if i < fragment.len() && fragment[i] != pattern[j] {
            if j != 0 {
                j = wzorzec.lps[j - 1];
            } else {
                i += 1;
            }
        }
    }

    count
}

// Implementacje zliczania
fn liczba_slow_sekwencyjny(sciezka_pliku: &str, slowo: &str) -> Metrics {
    let start_cpu = get_cpu_time();
    let start_time = Instant::now();
    let start_mem = get_memory_usage();

    let buffer = odczytaj_caly_plik(sciezka_pliku).unwrap();
    let fragmenty = podziel_na_fragmenty(&buffer);
    let wzorzec = przygotuj_wzorzec(slowo);

    let total = fragmenty.iter()
        .map(|&(start, end)| {
            let fragment = &buffer[start..end];
            liczba_slow_we_fragmencie(fragment, &wzorzec)
        })
        .sum();

    let czas = start_time.elapsed().as_secs_f64();
    let end_cpu = get_cpu_time();
    let end_mem = get_memory_usage();

    let num_cpus = unsafe {
        let mut sys_info = mem::zeroed();
        GetSystemInfo(&mut sys_info);
        sys_info.dwNumberOfProcessors as f64
    };

    Metrics {
        count: total,
        czas,
        cpu_usage: (end_cpu - start_cpu) / (czas * num_cpus) * 100.0,
        ram_usage: end_mem - start_mem,
    }
}

fn liczba_slow_arc_threads(sciezka_pliku: &str, slowo: &str, liczba_watkow: usize) -> Metrics {
    let start_cpu = get_cpu_time();
    let start_time = Instant::now();
    let start_mem = get_memory_usage();

    let buffer = Arc::new(odczytaj_caly_plik(sciezka_pliku).unwrap());
    let fragmenty = podziel_na_fragmenty(&buffer);
    let wzorzec = Arc::new(przygotuj_wzorzec(slowo));

    let chunk_size = (fragmenty.len() + liczba_watkow - 1) / liczba_watkow;
    let wyniki = Arc::new(Mutex::new(vec![0; liczba_watkow]));

    let handles: Vec<_> = fragmenty
        .chunks(chunk_size)
        .enumerate()
        .map(|(id, chunk)| {
            let wyniki = Arc::clone(&wyniki);
            let wzorzec = Arc::clone(&wzorzec);
            let buffer = Arc::clone(&buffer);
            let chunk = chunk.to_vec();

            std::thread::spawn(move || {
                let mut local_count = 0;
                
                for (start, end) in chunk {
                    let fragment = &buffer[start..end];
                    local_count += liczba_slow_we_fragmencie(fragment, &wzorzec);
                }

                wyniki.lock().unwrap()[id] = local_count;
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }

    let total: i32 = wyniki.lock().unwrap().iter().sum();
    
    let czas = start_time.elapsed().as_secs_f64();
    let end_cpu = get_cpu_time();
    let end_mem = get_memory_usage();

    let num_cpus = unsafe {
        let mut sys_info = mem::zeroed();
        GetSystemInfo(&mut sys_info);
        sys_info.dwNumberOfProcessors as f64
    };

    Metrics {
        count: total,
        czas,
        cpu_usage: (end_cpu - start_cpu) / (czas * num_cpus) * 100.0,
        ram_usage: end_mem - start_mem,
    }
}

fn liczba_slow_rayon(sciezka_pliku: &str, slowo: &str, liczba_watkow: usize) -> Metrics {
    let start_cpu = get_cpu_time();
    let start_time = Instant::now();
    let start_mem = get_memory_usage();

    let buffer = odczytaj_caly_plik(sciezka_pliku).unwrap();
    let fragmenty = podziel_na_fragmenty(&buffer);
    let wzorzec = przygotuj_wzorzec(slowo);

    // Usunięto inicjalizację puli - używamy domyślnej konfiguracji
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(liczba_watkow)
        .build()
        .unwrap();

    let total: i32 = pool.install(|| {
        fragmenty.par_iter()
            .map(|&(start, end)| {
                let fragment = &buffer[start..end];
                liczba_slow_we_fragmencie(fragment, &wzorzec)
            })
            .sum()
    });

    let czas = start_time.elapsed().as_secs_f64();
    let end_cpu = get_cpu_time();
    let end_mem = get_memory_usage();

    let num_cpus = unsafe {
        let mut sys_info = mem::zeroed();
        GetSystemInfo(&mut sys_info);
        sys_info.dwNumberOfProcessors as f64
    };

    Metrics {
        count: total,
        czas,
        cpu_usage: (end_cpu - start_cpu) / (czas * num_cpus) * 100.0,
        ram_usage: end_mem - start_mem,
    }
}

pub fn liczenie_slow() {
    // Ustawienie kodowania UTF-8 dla konsoli
    unsafe {
        winapi::um::wincon::SetConsoleOutputCP(65001);
    }

    // Pobierz dane od użytkownika
    let mut nazwa_uzytkownika = String::new();
    println!("Podaj nazwe uzytkownika: ");
    io::stdin().read_line(&mut nazwa_uzytkownika).unwrap();
    let nazwa_uzytkownika = nazwa_uzytkownika.trim();

    let mut liczba_watkow = String::new();
    println!("Podaj ilosc watkow: ");
    io::stdin().read_line(&mut liczba_watkow).unwrap();
    let liczba_watkow: usize = liczba_watkow.trim().parse().unwrap();

    let mut liczba_slow = String::new();
    println!("Podaj ilosc slow do sprawdzenia: ");
    io::stdin().read_line(&mut liczba_slow).unwrap();
    let liczba_slow: usize = liczba_slow.trim().parse().unwrap();

    let mut slowa = Vec::with_capacity(liczba_slow);
    for i in 0..liczba_slow {
        let mut slowo = String::new();
        println!("Podaj {}. slowo: ", i + 1);
        io::stdin().read_line(&mut slowo).unwrap();
        slowa.push(slowo.trim().to_string());
    }

    // Skonstruuj pełną ścieżkę do pliku
    let mut sciezka_pliku = String::new();
    println!("Podaj sciezke do pliku: ");
    io::stdin().read_line(&mut sciezka_pliku).unwrap();
    let sciezka_pliku = format!(
        "C:\\Users\\{}\\Desktop\\{}",
        nazwa_uzytkownika,
        sciezka_pliku.trim()
    );

    // Zmienne do podsumowania
    let mut total_seq = 0;
    let mut total_arcthr = 0;
    let mut total_ray = 0;
    let mut time_seq = 0.0;
    let mut time_arcthr = 0.0;
    let mut time_ray = 0.0;
    let mut cpu_seq = 0.0;
    let mut cpu_arcthr = 0.0;
    let mut cpu_ray = 0.0;
    let mut ram_seq = 0;
    let mut ram_arcthr = 0;
    let mut ram_ray = 0;

    for slowo in &slowa {
        // Wywołaj wszystkie implementacje
        let result_seq = liczba_slow_sekwencyjny(&sciezka_pliku, slowo);
        let result_arcthr = liczba_slow_arc_threads(&sciezka_pliku, slowo, liczba_watkow);
        let result_ray = liczba_slow_rayon(&sciezka_pliku, slowo, liczba_watkow);

        // Wyświetl wyniki dla bieżącego słowa
        println!("\nSlowo: {}", slowo);
        println!(
            "Sekwencyjnie: {} (czas: {:.2}s, CPU: {:.1}%, RAM: {} B)",
            result_seq.count, result_seq.czas, result_seq.cpu_usage, result_seq.ram_usage
        );
        println!(
            "Arc/Threads: {} (czas: {:.2}s, CPU: {:.1}%, RAM: {} B)",
            result_arcthr.count, result_arcthr.czas, result_arcthr.cpu_usage, result_arcthr.ram_usage
        );
        println!(
            "Rayon: {} (czas: {:.2}s, CPU: {:.1}%, RAM: {} B)",
            result_ray.count, result_ray.czas, result_ray.cpu_usage, result_ray.ram_usage
        );

        // Aktualizuj statystyki podsumowujące
        total_seq += result_seq.count;
        total_arcthr += result_arcthr.count;
        total_ray += result_ray.count;

        time_seq += result_seq.czas;
        time_arcthr += result_arcthr.czas;
        time_ray += result_ray.czas;

        cpu_seq += result_seq.cpu_usage;
        cpu_arcthr += result_arcthr.cpu_usage;
        cpu_ray += result_ray.cpu_usage;

        ram_seq += result_seq.ram_usage;
        ram_arcthr += result_arcthr.ram_usage;
        ram_ray += result_ray.ram_usage;
    }

    // Wyświetl podsumowanie globalne
    let avg_cpu_seq = cpu_seq / slowa.len() as f64;
    let avg_cpu_arcthr = cpu_arcthr / slowa.len() as f64;
    let avg_cpu_omp = cpu_ray / slowa.len() as f64;

    println!("\nPodsumowanie:");
    println!(
        "Sekwencyjnie: {} (czas: {:.2}s, średnie CPU: {:.1}%, RAM: {} B)",
        total_seq, time_seq, avg_cpu_seq, ram_seq
    );
    println!(
        "Threading: {} (czas: {:.2}s, średnie CPU: {:.1}%, RAM: {} B)",
        total_arcthr, time_arcthr, avg_cpu_arcthr, ram_arcthr
    );
    println!(
        "Rayon: {} (czas: {:.2}s, średnie CPU: {:.1}%, RAM: {} B)",
        total_ray, time_ray, avg_cpu_omp, ram_ray
    );
}