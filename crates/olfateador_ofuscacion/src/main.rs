// SPDX-License-Identifier: MIT
// Copyright (c) Juan Carlos Isaza
//! Hook PostToolUse. Lee la carga por stdin, huele el resultado, y si hay
//! ofuscación emite un aviso por `additionalContext` (el único canal medido
//! que llega al modelo; ver CLAUDE.md, medición 2026-08-05). NUNCA bloquea:
//! sale 0 siempre. Ante entrada rara, calla y sale 0 (es advisory).

use std::io::Read;
use std::time::SystemTime;

use olfateador_ofuscacion::{detectar, extraer_texto, redactar_aviso, ruta_entrada};
use serde_json::Value;

fn main() {
    let mut entrada = String::new();
    if std::io::stdin().read_to_string(&mut entrada).is_err() {
        std::process::exit(0);
    }
    let raiz: Value = match serde_json::from_str(&entrada) {
        Ok(v) => v,
        Err(_) => std::process::exit(0),
    };

    let herramienta = raiz
        .get("tool_name")
        .and_then(Value::as_str)
        .unwrap_or("desconocida");

    let mut texto = String::new();
    if let Some(resp) = raiz.get("tool_response") {
        extraer_texto(resp, &mut texto);
    }
    if texto.is_empty() {
        std::process::exit(0);
    }

    let ruta = ruta_entrada(&raiz);
    let hallazgos = detectar(&texto, ruta.as_deref());
    if hallazgos.is_empty() {
        std::process::exit(0);
    }

    let mut aviso = redactar_aviso(herramienta, &hallazgos);
    if let Some(nota) = binario_desactualizado() {
        aviso = format!("{nota}\n{aviso}");
    }

    let salida = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": aviso
        }
    });
    println!("{salida}");
    std::process::exit(0);
}

/// Un binario viejo junto a una fuente nueva se ve idéntico a un guardián
/// al día. Si algún .rs de `src/` es más reciente que este ejecutable, lo dice
/// DENTRO del propio aviso en vez de callarlo.
fn binario_desactualizado() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let exe_mtime = exe.metadata().ok()?.modified().ok()?;
    // exe = <crate>/target/release/olfateador_ofuscacion
    let src = exe.parent()?.parent()?.parent()?.join("src");
    let mut mas_nuevo = SystemTime::UNIX_EPOCH;
    visitar_rs(&src, &mut mas_nuevo);
    if mas_nuevo > exe_mtime {
        Some("[⚠ olfateador: la fuente es más nueva que el binario — recompílame con `cargo build --release`]".to_string())
    } else {
        None
    }
}

fn visitar_rs(dir: &std::path::Path, mas_nuevo: &mut SystemTime) {
    let Ok(entradas) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entradas.flatten() {
        let ruta = e.path();
        if ruta.is_dir() {
            visitar_rs(&ruta, mas_nuevo);
        } else if ruta.extension().is_some_and(|x| x == "rs") {
            if let Ok(m) = e.metadata().and_then(|md| md.modified()) {
                if m > *mas_nuevo {
                    *mas_nuevo = m;
                }
            }
        }
    }
}
