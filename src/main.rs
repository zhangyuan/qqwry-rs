use qqwry::Qqwry;
use std::env;

fn main() {
    let qqwry = Qqwry::new("data/qqwry.dat").expect("Cannot open data/qqwry.dat");
    let ip = env::args().nth(1).expect("ip is missing");

    match qqwry.lookup(&ip) {
        Ok((location, info)) => println!("{}, {}", location, info),
        Err(e) => eprintln!("{}", e),
    }
}
