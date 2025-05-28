# Build Script 
build:
  # Calls the just command in crates/comrade-component (just build): 
  just crates/comrade-component/build

test:
  cargo test --all --workspace 
  just crates/bs-peer/test-web

