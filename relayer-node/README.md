# Relayer Node for InterChain

To run 

1. Build the project
```
cargo build
```

2. Run the project
```
cargo run
```

3. Tests

```
cargo test -- --test test_eth_sep_to_arb_sep --nocapture
cargo test -- --test test_arb_sep_to_eth_sep --nocapture
```