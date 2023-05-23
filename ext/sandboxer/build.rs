// Copyright (c) 2023 Unibg Seclab (https://seclab.unibg.it)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

use libbpf_cargo::SkeletonBuilder;

use std::fs::create_dir_all;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;

const SRC: &str = "./src/bpf/restrictor.bpf.c";

fn gen_kernel_defs() -> Result<()> {
  // Generate kernel definitions
  let mut gen_cmd = Command::new("bpftool");
  gen_cmd
    .arg("btf")
    .arg("dump")
    .arg("file")
    .arg("/sys/kernel/btf/vmlinux")
    .arg("format")
    .arg("c");
  let output = gen_cmd.output().expect("Failed to run command");

  // Save the definitions to file
  let mut f = File::create("src/bpf/vmlinux.h")?;
  f.write_all(&output.stdout)?;

  Ok(())
}

fn gen_bindings() {
  let out_path = PathBuf::from("./src/bpf/bindings.rs");

  // Generate
  let bindings = bindgen::builder()
    .header("./src/bindings.h")
    .derive_default(true)
    .derive_eq(true)
    .derive_partialeq(true)
    .default_enum_style(bindgen::EnumVariation::Rust {
      non_exhaustive: false,
    })
    .constified_enum_module("f_buffer")
    .clang_arg("-Isrc/bpf/include")
    .clang_arg("-Wno-unknown-attributes")
    .clang_arg("-target")
    .clang_arg("bpf")
    .ignore_functions()
    .generate()
    .expect("Failed to generate bindings");

  // Save bindings
  bindings
    .write_to_file(out_path)
    .expect("Failed to save bindings");
}

fn gen_skel() -> Result<()> {
  create_dir_all("./src/bpf/.output")?;
  let skel = Path::new("./src/bpf/.output/restrictor.skel.rs");
  SkeletonBuilder::new(SRC).generate(&skel)?;
  Ok(())
}

fn main() -> Result<()> {
  gen_kernel_defs()?;
  gen_bindings();
  gen_skel()?;
  Ok(())
}
