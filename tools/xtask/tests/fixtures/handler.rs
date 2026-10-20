#![cfg_attr(windows, windows_subsystem = "windows")]
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args != ["tls", "status"] { std::process::exit(19); }
    let mut ready = std::env::current_exe().unwrap().into_os_string();
    ready.push(".ready");
    if !std::path::Path::new(&ready).is_file() {
        eprintln!("Synthetic profile is missing");
        std::process::exit(23);
    }
    println!("Synthetic profile validated");
}
