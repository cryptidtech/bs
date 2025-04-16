#![allow(dead_code)]
use convert_case::{Case, Converter};
use serde::Deserialize;
use std::{fs::File, io::Write, path::PathBuf};

#[derive(Debug, Deserialize)]
struct Record {
    name: String,
    tag: String,
    code: String,
    status: String,
    description: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut tpb = pb.clone();

    // input path
    tpb.push("table.csv");

    // output path
    pb.push("src");
    pb.push("table_gen.rs");
    println!("loading multicodecs table from {}", tpb.display());
    println!("cargo:rerun-if-changed={}", tpb.display());

    let inf = File::open(tpb)?;
    let mut f = File::create(pb)?;

    let mut rdr = csv::Reader::from_reader(inf);

    let conv = Converter::new().to_case(Case::Pascal); //.set_delim("_");

    writeln!(f, "build_codec_enum! {{")?;
    for row in rdr.deserialize() {
        let rec: Record = row?;
        writeln!(
            f,
            "\t{} => ({}, \"{}\"),",
            rec.code.trim(),
            conv.convert(rec.name.clone()),
            rec.name
        )?;
    }
    writeln!(f, "}}")?;

    // generate the code for src/table_gen.rs from the multicodecs .csv file
    Ok(())
}
