cargo clean
cargo build --verbose && cargo build --verbose --release
cargo run --verbose -- --verbose --pattern "fop" --out ./out/fop_release && cargo run --verbose --release -- --verbose --pattern "fop" --out ./out/fop_dev