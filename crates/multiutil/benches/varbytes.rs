use criterion::{black_box, criterion_group, criterion_main, Criterion};
use multiutil::{Varbytes, VarbytesIter};

fn varbytes(c: &mut Criterion) {
    let input: Vec<u8> = vec![1u8; 4096]; // 4KB of 1's
    c.bench_function("Varbytes", |b| {
        b.iter(|| {
            let v: Vec<u8> = Varbytes(input.clone()).into();
            black_box(v);
        })
    });
}

fn varbytesiter(c: &mut Criterion) {
    let input: Vec<u8> = vec![1u8; 4096]; // 4KB of 1's

    c.bench_function("VarbytesIter", |b| {
        b.iter(|| {
            let v: Vec<u8> = VarbytesIter::from(&input).collect();
            black_box(v);
        })
    });
}

criterion_group!(benches, varbytes, varbytesiter);
criterion_main!(benches);
