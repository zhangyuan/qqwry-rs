use qqwry::Qqwry;
use std::env;

fn main() {
    let database_path = env::args().nth(1).expect("database path is missing");
    let qqwry = Qqwry::new(database_path.as_str()).expect("Cannot open databse file");
    let ip = env::args().nth(2).expect("ip is missing");

    match qqwry.lookup(&ip) {
        Ok((location, isp)) => println!("{}, {}", location, isp),
        Err(e) => eprintln!("{}", e),
    }
}
