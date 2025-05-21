use qqwry::Qqwry;
use std::env;

fn main() {
    let qqwry = Qqwry::new("data/qqwry.dat").expect("Cannot open data/qqwry.dat");
    let ip = env::args().nth(1).expect("ip is missing");

    match qqwry.lookup(&ip) {
        Ok((country, region)) => println!("{}, {}", country, region),
        Err(e) => eprintln!("{}", e),
    }
}
