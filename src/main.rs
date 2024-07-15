use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use clap::Parser;

use slog::Drain;

#[derive(Debug, Clone)]
enum Target {
    Ipv6(Ipv6Addr),
    Ipv4(Ipv4Addr),
    Name(String),
}

fn parse_target(arg: &str) -> Result<Target, String> {
    match arg.parse() {
        Ok(addr) => match addr {
            IpAddr::V4(addr) => Ok(Target::Ipv4(addr)),
            IpAddr::V6(addr) => Ok(Target::Ipv6(addr)),
        },
        Err(_) => Ok(Target::Name(arg.to_string())),
    }
}

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Where to send IP packets.
    #[arg(short, value_parser = parse_target)]
    target: Option<Target>,

    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,

    /// Print the discovered path.
    #[arg(short, long, default_value_t = false)]
    path: bool,

    /// Maximum number of consecutive timeouts before considering a hop unreachable.
    #[arg(long, default_value_t = 3)]
    hop_timeouts: u32,

    /// Number of probes sent per hop to determine bleaching status.
    #[arg(long, default_value_t = 3)]
    probe_count: u32,

    /// Publish results to a repository at the (optionally) specified URL.
    #[arg(long, require_equals = true, default_missing_value = "data.cerfca.st", num_args = 0..=1,)]
    publish: Option<String>,

    /// Allow bleaching detection to continue even if there is a path divergence.
    #[arg(long, default_value_t = false)]
    permissive: bool,

    /// Don't let unreachable hops stop us from continuing until we hit a certain number of hops.
    #[arg(long, require_equals = true, default_missing_value = "30", num_args = 0..=1,)]
    go: Option<u8>,
}

fn random_ip() -> String {
    let a = rand::random::<u8>() % 255;
    let b = rand::random::<u8>() % 255;
    let c = rand::random::<u8>() % 255;
    let d = rand::random::<u8>() % 255;

    format!("{}.{}.{}.{}", a, b, c, d).to_string()
}

fn main() {
    let args = Cli::parse();

    let has_go_mode = args.go.is_some();

    if has_go_mode && args.debug > 1 {
        println!("Enabling go mode.");
    }

    let cli_target = match args.target {
        Some(t) => t,
        None => {
            let parse_result = parse_target(&random_ip());
            println!(
                "Using a random IP as the target: {:?}",
                parse_result.clone().unwrap()
            );
            parse_result.unwrap()
        }
    };

    let target = match cli_target {
        Target::Name(name) => {
            let hostname_with_dummy_port = name.clone() + ":80";

            let server_ips = hostname_with_dummy_port.to_socket_addrs();

            if let Err(resolution_error) = server_ips {
                println!("Error resolving target: {:?}", resolution_error);
                return;
            }

            let mut sv: Vec<SocketAddr> = vec![];
            server_ips.unwrap().for_each(|f| sv.push(f));

            let resolution_result_count = sv.len();
            let server_ip = sv[0];
            if resolution_result_count > 1 {
                println!(
                    "Warning: There were multiple IP addresses resolved from {:?}; using {:?}",
                    name.clone(),
                    server_ip.ip()
                );
            }
            match server_ip.ip() {
                IpAddr::V4(addr) => bleecn::Target::Ipv4(addr),
                IpAddr::V6(addr) => bleecn::Target::Ipv6(addr),
            }
        }
        Target::Ipv4(addr) => bleecn::Target::Ipv4(addr),
        Target::Ipv6(addr) => bleecn::Target::Ipv6(addr),
    };
    let decorator = slog_term::PlainSyncDecorator::new(std::io::stdout());
    let drain = slog_term::FullFormat::new(decorator).build().filter_level(
        if args.debug > 0 {
            slog::Level::Info
        } else {
            slog::Level::Warning
        }
    ).fuse();
    let logger = slog::Logger::root(drain, slog::o!("version" => "0.5"));

    let test_result = bleecn::bleecn(
        target,
        args.probe_count,
        args.go,
        args.hop_timeouts,
        args.permissive,
        &logger,
    );

    if let Err(test_result_err) = test_result {
        eprintln!("There was an error running the test: {}", test_result_err);
        return;
    }

    let test_result = test_result.unwrap();

    if args.debug > 0 || args.path {
        println!("path: {}", test_result.path);
    }
    if let Some(bleeched_hop) = test_result.bleeched_hop.clone() {
        println!("bleeching hop: {:?}", bleeched_hop);
    } else {
        println!("No ECN bleeching detected.");
    }

    if let Some(publish_url) = args.publish {
        if args.debug > 1 {
            println!("Publishing results to {}.", publish_url);
        }

        let json_test_result = serde_json::to_string(&test_result).unwrap();
        let json_test_result_pretty = serde_json::to_string_pretty(&test_result).unwrap();

        let client = reqwest::blocking::Client::new();
        let result_post_status = client
            .post(format!("https://{}/api/publish/bleecn", publish_url))
            .body(json_test_result.clone())
            .send();
        if let Err(e) = result_post_status {
            eprintln!("Error: There was an error posting the result: {}", e);
        } else {
            let result_post_status = result_post_status.unwrap();
            if result_post_status.status().is_success() {
                if args.debug > 1 {
                    println!(
                        "The result posted to {} looked like: {}",
                        publish_url, json_test_result_pretty
                    );
                }
                println!("Results successfully published to {}.", publish_url);
            } else {
                eprintln!(
                    "Error: Server reported {} when posting the results.",
                    result_post_status.status()
                );
            }
        }
    }
}
