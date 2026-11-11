// SPDX-License-Identifier: MIT
//! Medidor de latencia del detector, zero-dep (std solo). Corre `detectar` sobre
//! una salida de herramienta representativa (texto limpio tipo README/código) y
//! reporta ns/op y ops/s. Reproducible: `cargo run --release --bin latencia`.
//! No es criterion (evitamos la dependencia): mide la mediana de varias tandas.

use std::time::Instant;

use olfateador_ofuscacion::detectar;

fn main() {
    // Carga representativa: ~4 KB de texto normal (lo que de verdad ingiere el
    // hook casi siempre), con algo de markdown y código.
    let unidad = "## Section\nRun `make build` to compile. See https://example.com/docs?v=2 for details.\n\
                  fn main() { let x = compute(42); println!(\"{x}\"); }\n- a list item with some prose, acentos: programación ñoño\n";
    let texto = unidad.repeat(32); // ~4 KB

    let calentamiento = 1_000;
    for _ in 0..calentamiento {
        std::hint::black_box(detectar(std::hint::black_box(&texto), None));
    }

    let tandas = 9;
    let iters = 20_000;
    let mut medidas: Vec<f64> = Vec::with_capacity(tandas);
    for _ in 0..tandas {
        let t0 = Instant::now();
        for _ in 0..iters {
            std::hint::black_box(detectar(std::hint::black_box(&texto), None));
        }
        let ns_por_op = t0.elapsed().as_nanos() as f64 / iters as f64;
        medidas.push(ns_por_op);
    }
    medidas.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mediana = medidas[medidas.len() / 2];
    let p_peor = medidas[medidas.len() - 1];

    let mb_s = texto.len() as f64 / (mediana / 1000.0); // bytes/µs = MB/s
    println!("payload: {} bytes de texto representativo", texto.len());
    println!("mediana: {:.1} µs/scan  ({:.0} ns)", mediana / 1000.0, mediana);
    println!("peor tanda: {:.1} µs/scan", p_peor / 1000.0);
    println!("throughput (mediana): {mb_s:.0} MB/s");
}
