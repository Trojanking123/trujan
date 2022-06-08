#![forbid(unsafe_code)]

use clap::{ Command, Arg};

mod error;
mod protocol;
mod proxy;

#[tokio::main]
async fn main() {
    let matches = Command::new("trojan-r")
        .version("v0.1.0")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .required(true)
                .takes_value(true)
                .help(".toml config file name"),
        )
        .author("Developed by @p4gefau1t (Page Fault)")
        .about("An unidentifiable mechanism that helps you bypass GFW")
        .get_matches();
    let filename = matches.value_of("config").unwrap().to_string();
    log::debug!("fdsfasdfaf");
    if let Err(e) = proxy::launch_from_config_filename(filename).await {
        println!("failed to launch proxy: {}", e);
    }
}
