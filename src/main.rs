use crypt_client::repl::{Repl, RustyLineReplDriver};

fn main() {
    let mut repl = Repl::new(RustyLineReplDriver::default());
    repl.print_usage();
    repl.run_loop().unwrap();
}
