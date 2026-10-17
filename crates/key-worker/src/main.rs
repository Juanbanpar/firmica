fn main() {
    if std::env::args_os().skip(1).collect::<Vec<_>>() != ["--stdio"]
        || firmica_key_worker::serve().is_err()
    {
        std::process::exit(1);
    }
}
