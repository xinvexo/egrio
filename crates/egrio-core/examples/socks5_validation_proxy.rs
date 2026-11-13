use egrio_core::validation::{parse_socks5_validation_proxy_args, run_socks5_validation_proxy};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let config = parse_socks5_validation_proxy_args(&args).unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(2);
    });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(error) = runtime.block_on(run_socks5_validation_proxy(config)) {
        eprintln!("SOCKS5 validation proxy failed: {error}");
        std::process::exit(1);
    }
}
