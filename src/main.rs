use std::io;

mod liczenie_slow;
mod rsa_aes;

fn main() {
    println!("Wybierz opcje:");
    println!("1. Liczenie słów w pliku");
    println!("2. Szyfrowanie RSA/AES");

    let mut wybor = String::new();
    io::stdin().read_line(&mut wybor).expect("Błąd czytania linii");
    let wybor: i32 = match wybor.trim().parse() {
        Ok(num) => num,
        Err(_) => {
            println!("Nieprawidłowy wybór");
            return;
        }
    };

    match wybor {
        1 => liczenie_slow::liczenie_slow(),
        2 => rsa_aes::szyfrowanie(),
        _ => println!("Nieprawidlowy wybor"),
    }
}