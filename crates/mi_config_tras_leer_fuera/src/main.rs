// SPDX-License-Identifier: MIT
// Copyright (c) Juan Carlos Isaza
//! Hook PreToolUse sobre Write/Edit/MultiEdit/NotebookEdit. Avisa (NUNCA
//! bloquea; sale 0 siempre) cuando el asistente escribe en su config de alta
//! potencia tras leer de fuera en el mismo turno. El aviso va por
//! `additionalContext`, el único canal medido que llega al modelo.

use mi_config_tras_leer_fuera::evaluar;
use serde_json::Value;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

fn main() {
    let mut entrada = String::new();
    if std::io::stdin().read_to_string(&mut entrada).is_err() {
        std::process::exit(0);
    }
    let raiz: Value = match serde_json::from_str(&entrada) {
        Ok(v) => v,
        Err(_) => std::process::exit(0),
    };
    let home = match std::env::var_os("HOME") {
        Some(h) => PathBuf::from(h),
        None => std::process::exit(0),
    };

    if let Some(mut aviso) = evaluar(&raiz, &home) {
        if let Some(nota) = binario_desactualizado() {
            aviso = format!("{nota}\n{aviso}");
        }
        let salida = serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": aviso
            }
        });
        println!("{salida}");
    }
    std::process::exit(0);
}

/// Un binario viejo junto a una fuente nueva se ve idéntico a un
/// guardián al día. Si algún `.rs` de `src/` es más reciente que el ejecutable,
/// lo dice DENTRO del propio aviso en vez de callarlo.
fn binario_desactualizado() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let exe_mtime = exe.metadata().ok()?.modified().ok()?;
    // exe = <crate>/target/release/mi_config_tras_leer_fuera
    let src = exe.parent()?.parent()?.parent()?.join("src");
    let mut mas_nuevo = SystemTime::UNIX_EPOCH;
    visitar_rs(&src, &mut mas_nuevo);
    if mas_nuevo > exe_mtime {
        Some("[⚠ mi_config_tras_leer_fuera: la fuente es más nueva que el binario — recompílame con `cargo build --release`]".to_string())
    } else {
        None
    }
}

fn visitar_rs(dir: &Path, mas_nuevo: &mut SystemTime) {
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
