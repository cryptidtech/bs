use std::{env, fs, path::Path};

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let files = fs::read_dir("examples/wast")
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "wast" || ext == "wasm")
                .unwrap_or(false)
        });

    for f in files {
        // Copy the WAST/WASM files to the output directory
        let input_path = f.path();
        let file_name = input_path.file_name().unwrap().to_str().unwrap();
        let output_path = Path::new(&out_dir).join(file_name);
        fs::copy(&input_path, &output_path).expect("Failed to copy WAST/WASM file");

        // Ensure that cargo reruns if the .wast file changes
        println!("cargo:rerun-if-changed={}", input_path.display());
    }
}
