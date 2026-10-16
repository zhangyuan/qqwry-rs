use std::env;
use std::io::{self, BufRead};
use std::process::ExitCode;

use qqwry::Qqwry;

const USAGE: &str = "\
qqwry — look up IPv4 addresses in a 纯真 (qqwry.dat) database

Usage:
    qqwry <database> <ip>...   look up one or more addresses
    qqwry <database>           read addresses from stdin, one per line
    qqwry -h | --help          show this help

Output:
    a single address prints \"location, isp\";
    several addresses (or stdin) print \"ip, location, isp\" per line.
";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();

    if args
        .first()
        .is_some_and(|arg| arg == "-h" || arg == "--help")
    {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    let Some((database_path, ips)) = args.split_first() else {
        print!("{USAGE}");
        return ExitCode::FAILURE;
    };

    let qqwry = match Qqwry::new(database_path) {
        Ok(qqwry) => qqwry,
        Err(error) => {
            eprintln!("error: cannot open {database_path}: {error}");
            return ExitCode::FAILURE;
        }
    };

    // Keep the historical single-address output compact.
    if let [ip] = ips {
        return match qqwry.lookup(ip) {
            Ok((location, isp)) => {
                println!("{location}, {isp}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("{ip}: {error}");
                ExitCode::FAILURE
            }
        };
    }

    let mut failed = false;
    if ips.is_empty() {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            let Ok(line) = line else {
                eprintln!("error: cannot read stdin");
                return ExitCode::FAILURE;
            };
            let ip = line.trim();
            if !ip.is_empty() {
                failed |= lookup_one(&qqwry, ip);
            }
        }
    } else {
        for ip in ips {
            failed |= lookup_one(&qqwry, ip);
        }
    }

    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Looks up `ip`, printing the result. Returns `true` on failure.
fn lookup_one(qqwry: &Qqwry, ip: &str) -> bool {
    match qqwry.lookup(ip) {
        Ok((location, isp)) => {
            println!("{ip}, {location}, {isp}");
            false
        }
        Err(error) => {
            eprintln!("{ip}: {error}");
            true
        }
    }
}
