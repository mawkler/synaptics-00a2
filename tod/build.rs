// SPDX-License-Identifier: LGPL-2.1-or-later
//! Compiles the C half of the TOD module against libfprint-TOD

const LIBRARIES: [&str; 3] = ["libfprint-2-tod-1", "gio-2.0", "gusb"];

fn main() {
    let mut build = cc::Build::new();
    for library in LIBRARIES {
        let found = pkg_config::Config::new()
            .cargo_metadata(false)
            .probe(library)
            .unwrap_or_else(|e| panic!("{library}: {e}"));
        for path in found.include_paths {
            // nixpkgs' pkg-config drops libfprint-2-tod-1's Requires.private
            // cflags, so add the public libfprint-2 headers next to tod-1/
            if path.ends_with("tod-1") {
                build.include(path.parent().expect("tod-1 has a parent"));
            }
            build.include(path);
        }
    }
    build
        .file("src/syna_00a2_tod.c")
        .warnings(true)
        .flag_if_supported("-Wno-unused-parameter")
        .compile("syna_00a2_shim");
    // Linked after the C archive that uses them, so --as-needed keeps them
    for library in LIBRARIES {
        pkg_config::probe_library(library).unwrap_or_else(|e| panic!("{library}: {e}"));
    }
    println!("cargo:rerun-if-changed=src/syna_00a2_tod.c");
}
