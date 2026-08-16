use clap::Parser;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = audit_local::Cli::parse();
    let code = match audit_local::dispatch(cli.command) {
        Ok(outcome) => outcome.exit_code(),
        Err(err) => {
            tracing::error!("{err:#}");
            1
        }
    };
    std::process::exit(code);
}
