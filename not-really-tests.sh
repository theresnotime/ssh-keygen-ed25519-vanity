cargo clean
cargo build --verbose && cargo build --verbose --release
cargo run --verbose -- "fop" ./out/fop_release && cargo run --verbose --release -- "fop" ./out/fop_dev