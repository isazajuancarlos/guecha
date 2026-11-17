// SPDX-License-Identifier: MIT
// Copyright (c) Juan Carlos Isaza
//! Banco del guardián: pareja ROJA/VERDE por la MISMA costura que el camino
//! real (`evaluar` lee `transcript_path` del JSON de entrada, igual que main).
//! Dos discriminadores cruciales:
//!   - `verde_externa_en_turno_previo`: un hook que ignorara la frontera del
//!     turno humano lo pondría ROJO (valida la lógica «desde tu último mensaje»).
//!   - `verde_destino_no_protegido`: valida la lógica de rutas.
//!
//! Sale != 0 si algún caso falla.

use mi_config_tras_leer_fuera::evaluar;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

fn escribir_transcript(dir: &Path, nombre: &str, filas: &[Value]) -> PathBuf {
    let ruta = dir.join(format!("{nombre}.jsonl"));
    let cuerpo: String = filas.iter().map(|f| f.to_string() + "\n").collect();
    std::fs::write(&ruta, cuerpo).unwrap();
    ruta
}

fn humano(txt: &str) -> Value {
    json!({"type":"user","message":{"role":"user","content":txt}})
}
fn resultado() -> Value {
    json!({"type":"user","toolUseResult":{"ok":1},
           "message":{"role":"user","content":[{"type":"tool_result","content":"ok"}]}})
}
fn usa(name: &str, input: Value) -> Value {
    json!({"type":"assistant","message":{"role":"assistant",
           "content":[{"type":"tool_use","name":name,"input":input}]}})
}

fn raiz(transcript: &Path, home: &Path, destino: &str) -> Value {
    let d = destino.replace("{HOME}", home.to_str().unwrap());
    json!({"tool_name":"Write","tool_input":{"file_path":d},
           "transcript_path":transcript.to_str().unwrap()})
}

fn chequear(
    dir: &Path,
    home: &Path,
    nombre: &str,
    filas: Vec<Value>,
    destino: &str,
    espera_aviso: bool,
) -> bool {
    let t = escribir_transcript(dir, nombre, &filas);
    let r = raiz(&t, home, destino);
    let dio = evaluar(&r, home).is_some();
    let ok = dio == espera_aviso;
    println!(
        "{}  {:<34}  espera={}  dio={}",
        if ok { "PASA" } else { "FALLA" },
        nombre,
        espera_aviso,
        dio
    );
    ok
}

fn raiz_bash(transcript: &Path, home: &Path, command: &str) -> Value {
    let c = command.replace("{HOME}", home.to_str().unwrap());
    json!({"tool_name":"Bash","tool_input":{"command":c},
           "transcript_path":transcript.to_str().unwrap()})
}

fn chequear_bash(
    dir: &Path,
    home: &Path,
    nombre: &str,
    filas: Vec<Value>,
    command: &str,
    espera: bool,
) -> bool {
    let t = escribir_transcript(dir, nombre, &filas);
    let r = raiz_bash(&t, home, command);
    let dio = evaluar(&r, home).is_some();
    let ok = dio == espera;
    println!(
        "{}  {:<34}  espera={}  dio={}",
        if ok { "PASA" } else { "FALLA" },
        nombre,
        espera,
        dio
    );
    ok
}

fn main() {
    let home = std::env::temp_dir().join("guardian_fixt_home");
    std::fs::create_dir_all(home.join(".claude/hooks")).unwrap();
    std::fs::create_dir_all(home.join(".claude/skills")).unwrap();
    let dir = std::env::temp_dir().join("probar_mi_config");
    std::fs::create_dir_all(&dir).unwrap();

    let skill_leida = format!("{}/.claude/skills/evil/SKILL.md", home.display());
    let mut fallos = 0;

    // ───── ROJO: DEBE avisar (config protegida + lectura externa en el turno) ─────
    for (n, filas, dest) in [
        (
            "rojo_web_a_claudemd",
            vec![humano("arregla el indexado"), usa("WebFetch", json!({"url":"http://x"}))],
            "{HOME}/.claude/CLAUDE.md",
        ),
        (
            "rojo_skill_a_settings",
            vec![humano("aplica la skill"), usa("Skill", json!({"skill":"foo"}))],
            "{HOME}/.claude/settings.json",
        ),
        (
            "rojo_mcp_a_hook",
            vec![humano("lee el correo"), usa("mcp__claude_ai_Gmail__get_message", json!({"id":"1"}))],
            "{HOME}/.claude/hooks/x.py",
        ),
        (
            "rojo_read_skill_a_claudemd",
            vec![humano("mira la skill"), usa("Read", json!({"file_path": skill_leida}))],
            "{HOME}/.claude/CLAUDE.md",
        ),
    ] {
        if !chequear(&dir, &home, n, filas, dest, true) {
            fallos += 1;
        }
    }

    // ───── VERDE: NO debe avisar ─────
    for (n, filas, dest) in [
        (
            "verde_sin_externa",
            vec![humano("edita el claude.md"), usa("Bash", json!({"command":"ls -l /home/user/project"}))],
            "{HOME}/.claude/CLAUDE.md",
        ),
        (
            "verde_destino_no_protegido",
            vec![humano("arregla"), usa("WebFetch", json!({"url":"http://x"}))],
            "/home/user/project/src/x.rs",
        ),
        (
            "verde_externa_en_turno_previo",
            vec![
                humano("investiga en la web"),
                usa("WebFetch", json!({"url":"http://x"})),
                resultado(),
                humano("ahora edita el claude.md"),
                usa("Bash", json!({"command":"cargo build"})),
            ],
            "{HOME}/.claude/CLAUDE.md",
        ),
        (
            "verde_read_proyecto_normal",
            vec![humano("revisa"), usa("Read", json!({"file_path":"/home/user/project/README.md"}))],
            "{HOME}/.claude/CLAUDE.md",
        ),
        (
            "verde_bash_local",
            vec![humano("edita"), usa("Bash", json!({"command":"grep -r foo /home/user/project2"}))],
            "{HOME}/.claude/CLAUDE.md",
        ),
    ] {
        if !chequear(&dir, &home, n, filas, dest, false) {
            fallos += 1;
        }
    }

    // ───── #5: bypass por Bash (redirección/escritura a config vía shell) ─────
    if !chequear_bash(
        &dir, &home, "rojo_bash_redirige_claudemd",
        vec![humano("investiga en la web"), usa("WebFetch", json!({"url":"http://x"}))],
        "echo pwned >> {HOME}/.claude/CLAUDE.md", true,
    ) {
        fallos += 1;
    }
    if !chequear_bash(
        &dir, &home, "rojo_bash_tee_a_hook",
        vec![humano("aplica la skill"), usa("Skill", json!({"skill":"foo"}))],
        "echo x | tee {HOME}/.claude/hooks/evil.py", true,
    ) {
        fallos += 1;
    }
    // VERDE: LEER la config (cat) no persiste nada → no debe avisar.
    if !chequear_bash(
        &dir, &home, "verde_bash_lee_config",
        vec![humano("mira la web"), usa("WebFetch", json!({"url":"http://x"}))],
        "cat {HOME}/.claude/CLAUDE.md", false,
    ) {
        fallos += 1;
    }
    // VERDE: escribir a /tmp (no es config protegida) → no debe avisar.
    if !chequear_bash(
        &dir, &home, "verde_bash_escribe_tmp",
        vec![humano("corre esto"), usa("WebFetch", json!({"url":"http://x"}))],
        "echo x > /tmp/nota.txt", false,
    ) {
        fallos += 1;
    }
    // ROJO (2º paso): LEE la primera config y ESCRIBE la segunda. Con `find` de
    // la primera ruta se escapaba; ahora se revisan todas.
    if !chequear_bash(
        &dir, &home, "rojo_bash_lee_una_escribe_otra",
        vec![humano("revisa"), usa("WebFetch", json!({"url":"http://x"}))],
        "cat {HOME}/.claude/CLAUDE.md; echo evil >> {HOME}/.claude/settings.json", true,
    ) {
        fallos += 1;
    }

    // ROJO (3º paso): redirección a VARIABLE que oculta el destino, nombrando
    // una config protegida → se trata como escritura.
    if !chequear_bash(
        &dir, &home, "rojo_bash_redirige_variable",
        vec![humano("corre"), usa("WebFetch", json!({"url":"http://x"}))],
        "P={HOME}/.claude/CLAUDE.md; echo evil > $P", true,
    ) {
        fallos += 1;
    }

    // ───── #6: evasión por SYMLINK — `atajo`→`.claude` esquivaba la huella ─────
    // La normalización léxica resolvía `.`/`..` pero NO symlinks; `resuelve`
    // canonicaliza el padre y lo cierra. Pareja roja/verde por la vía real.
    #[cfg(unix)]
    let casos_symlink = {
        use std::os::unix::fs::symlink;
        // (a) symlink de DIRECTORIO: `atajo`→`.claude`, destino `atajo/CLAUDE.md`.
        let atajo = home.join("atajo");
        let _ = std::fs::remove_file(&atajo);
        symlink(home.join(".claude"), &atajo).unwrap();
        if !chequear(
            &dir, &home, "rojo_symlink_a_claudemd",
            vec![humano("investiga en la web"), usa("WebFetch", json!({"url":"http://x"}))],
            &format!("{}/atajo/CLAUDE.md", home.display()), true,
        ) {
            fallos += 1;
        }
        // VERDE: symlink a un directorio NEUTRO (no config) NO debe avisar.
        let neutro = std::env::temp_dir().join("guardian_neutro");
        std::fs::create_dir_all(&neutro).unwrap();
        let otro = home.join("otro");
        let _ = std::fs::remove_file(&otro);
        symlink(&neutro, &otro).unwrap();
        if !chequear(
            &dir, &home, "verde_symlink_neutro",
            vec![humano("investiga en la web"), usa("WebFetch", json!({"url":"http://x"}))],
            &format!("{}/otro/CLAUDE.md", home.display()), false,
        ) {
            fallos += 1;
        }
        // (b) symlink del ÚLTIMO componente: `enlace`→`.claude/CLAUDE.md` (el fix
        // incompleto solo seguía el PADRE; canonicalize de la ruta completa sigue
        // el leaf). Requiere que el archivo real exista para seguirlo.
        let config_real = home.join(".claude/CLAUDE.md");
        std::fs::write(&config_real, "# fixture\n").unwrap();
        let enlace = home.join("enlace");
        let _ = std::fs::remove_file(&enlace);
        symlink(&config_real, &enlace).unwrap();
        if !chequear(
            &dir, &home, "rojo_leaf_symlink_a_claudemd",
            vec![humano("investiga en la web"), usa("WebFetch", json!({"url":"http://x"}))],
            &format!("{}/enlace", home.display()), true,
        ) {
            fallos += 1;
        }
        // VERDE: leaf symlink a un archivo NEUTRO → no es config, no debe avisar.
        let archivo_neutro = neutro.join("nota.txt");
        std::fs::write(&archivo_neutro, "x\n").unwrap();
        let enlace2 = home.join("enlace_neutro");
        let _ = std::fs::remove_file(&enlace2);
        symlink(&archivo_neutro, &enlace2).unwrap();
        if !chequear(
            &dir, &home, "verde_leaf_symlink_neutro",
            vec![humano("investiga en la web"), usa("WebFetch", json!({"url":"http://x"}))],
            &format!("{}/enlace_neutro", home.display()), false,
        ) {
            fallos += 1;
        }
        // (c) symlink COLGANTE: `colgante`→`.claude/settings.local.json` que NO
        // existe aún. Un Write lo CREA a través del enlace → envenena config.
        // canonicalize falla (destino ausente); hay que seguir el symlink igual.
        let colgante = home.join("colgante");
        let _ = std::fs::remove_file(&colgante);
        symlink(home.join(".claude/settings.local.json"), &colgante).unwrap();
        if !chequear(
            &dir, &home, "rojo_dangling_leaf_a_settings",
            vec![humano("investiga en la web"), usa("WebFetch", json!({"url":"http://x"}))],
            &format!("{}/colgante", home.display()), true,
        ) {
            fallos += 1;
        }
        // VERDE: colgante a destino NEUTRO inexistente → no es config, no avisa.
        let colg_neutro = home.join("colgante_neutro");
        let _ = std::fs::remove_file(&colg_neutro);
        symlink(neutro.join("inexistente.txt"), &colg_neutro).unwrap();
        if !chequear(
            &dir, &home, "verde_dangling_leaf_neutro",
            vec![humano("investiga en la web"), usa("WebFetch", json!({"url":"http://x"}))],
            &format!("{}/colgante_neutro", home.display()), false,
        ) {
            fallos += 1;
        }
        // (d) `..` DESPUÉS de un symlink de directorio: `s_hooks`→`.claude/hooks`,
        // destino `s_hooks/../CLAUDE.md`. El kernel: hooks→`..`→`.claude`→CLAUDE.md
        // = config. El colapso léxico de `..` ANTES de resolver lo mandaba a
        // `~/CLAUDE.md` (diferencial de parser) y se perdía.
        let s_hooks = home.join("s_hooks");
        let _ = std::fs::remove_file(&s_hooks);
        symlink(home.join(".claude/hooks"), &s_hooks).unwrap();
        if !chequear(
            &dir, &home, "rojo_dotdot_tras_symlink",
            vec![humano("investiga en la web"), usa("WebFetch", json!({"url":"http://x"}))],
            &format!("{}/s_hooks/../CLAUDE.md", home.display()), true,
        ) {
            fallos += 1;
        }
        // VERDE: mismo cruce pero a un nombre NO protegido → `.claude/README.md`.
        if !chequear(
            &dir, &home, "verde_dotdot_tras_symlink_neutro",
            vec![humano("investiga en la web"), usa("WebFetch", json!({"url":"http://x"}))],
            &format!("{}/s_hooks/../README.md", home.display()), false,
        ) {
            fallos += 1;
        }
        8
    };
    #[cfg(not(unix))]
    let casos_symlink = 0;

    println!("\n{} casos, {fallos} fallos", 15 + casos_symlink);
    if fallos > 0 {
        std::process::exit(1);
    }
}
