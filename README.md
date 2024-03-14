# Rust version of dx-toolkit

This should be better than the Python version.

First, install Rust: https://www.rust-lang.org/tools/install

The Cargo tool is Rust's package manager and tool for compiling and running code.

Use `cargo build` to download the dependencies and build the executable.

Execute `cargo run help` to see the usage for `dxrs`:

```
Usage: dxrs [OPTIONS] [COMMAND]

Commands:
  cd        Change directory
  describe  Show object metadata
  env       Environment listing
  format    Format app/asset JSON
  lint      Lint app/asset JSON
  login     Login to platform
  logout    Logout of platform
  ls        Directory listing
  pwd       Print working directory
  select    Select working project
  whoami    Identify currently logged in user
  wizard    Wizard for creating applets
  help      Print this message or the help of the given subcommand(s)

Options:
  -d, --debug
  -h, --help   Print help
```

Use `cargo run -- <command>` where the double-dash (`--`) separates Cargo's options from the options belonging to the commands.
For instance, there is a `-d|--debug` option you can use to get extra runtime information from some commands like _describe_:

```
cargo run -- -d desc analysis-GFfkqz0054JJG8p1GBpv7qGX --json
```

Use `cargo test` to run the test suite.

## Author

Ken Youens-Clark <kyclark@dnanexus.com>
