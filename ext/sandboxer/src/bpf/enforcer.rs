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

use super::hasher::Djb2;

use anyhow::{anyhow, bail, Result};

use libbpf_sys::{
  bpf_create_map, bpf_create_map_name, bpf_map_lookup_elem, bpf_map_update_elem,
};
use libbpf_sys::{
  BPF_ANY, BPF_EXIST, BPF_F_NO_PREALLOC, BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_HASH,
  BPF_NOEXIST,
};

use object::{Object, ObjectSymbol};

use plain::Plain;

mod raw {
  #![allow(non_upper_case_globals)]
  #![allow(non_camel_case_types)]
  #![allow(non_snake_case)]
  include!("bindings.rs");
}
use raw::{collision_key, path_wrapper};

use crate::bpf::restrictor::*;

use crate::policy::{MAX_DEPTH, POLICY_VECTOR};

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::os::raw::{c_char, c_void};
use std::path::Path;

use caps;

static mut SYNC: bool = false;

const DEBUG_LOG: bool = false;
const PATH_SIZE: usize = 4096;

/// Assign the bindings to a user defined type
type PolicyValue = path_wrapper;
type CollisionKey = collision_key;
/// Allow the plain crate to convert the structure to an array of Bytes
unsafe impl Plain for PolicyValue {}
unsafe impl Plain for CollisionKey {}

/// Retrieve the symbol of a user function to attach the UPROBE
fn get_symbol_address(so_path: &str, fn_name: &str) -> Result<usize> {
  let path = Path::new(so_path);
  let buffer = fs::read(path)?;
  let file = object::File::parse(buffer.as_slice())?;

  let mut symbols = file.symbols();
  let symbol = symbols
    .find(|symbol| {
      if let Ok(name) = symbol.name() {
        return name.contains(fn_name);
      }
      false
    })
    .ok_or(anyhow!("symbol not found"))?;

  Ok(symbol.address() as usize)
}

/// Uprobe attachment point for `containerize`.
#[no_mangle]
#[inline(never)]
pub extern "C" fn attach_policy_num(_pol_num: u32) {}

/// Increase max default eBPF program size before load
fn bump_memlock_rlimit() -> Result<()> {
  let rlimit = libc::rlimit {
    rlim_cur: 128 << 20,
    rlim_max: 128 << 20,
  };

  // Usually if permission is denied
  // TODO: check the permissions required to set the limit
  if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
    bail!("Cannot increase rlimit");
  }

  Ok(())
}

/// Interface to call the hasher module for Djb2
fn hash_string(buf: &[u8; PATH_SIZE]) -> u64 {
  let mut hasher = Djb2::default();
  hasher.write(buf);
  hasher.finish()
}

/// This function writes in the kernel the maps required to restric
/// access to files. After the maps have been compiled and
/// loaded, we only need to attach the eBPF program to a target
/// process.
fn write_maps(skel: &mut RestrictorSkel) -> Result<()> {
  unsafe {
    // policy_num variable
    let mut idx: u32;

    for i in 0..POLICY_VECTOR.len() {
      let mut colliding_paths: HashMap<(u64, i32), HashSet<[i8; PATH_SIZE]>> =
        HashMap::new();

      idx = i as u32;

      // Recover the policy denied list
      let policy = &POLICY_VECTOR[i].deny;

      let size: i32 = match policy {
        Some(denied_vec) => denied_vec.len().try_into()?,
        None => 0,
      };

      // If there is no denied vector we can skip this policy
      if size == 0 {
        continue;
      }

      match policy {
        Some(denied_vec) => {
          let sep : String = String::from("/");
          for filename in denied_vec.iter() {
            // Convert filename to buffer of bytes
            let mut buf: [u8; PATH_SIZE] = [0; PATH_SIZE];
            let mut sav_buf: [i8; PATH_SIZE] = [0; PATH_SIZE];

            let filename_len: usize = filename.as_bytes().len();

            // Only absolute paths allowed
            if filename_len > 0 && filename.as_bytes()[0] != sep.as_bytes()[0] {
                panic!("Filename: {} is not an absolute path. Only absolute paths are allowed", filename);
            }
            
            for buf_idx in 0..filename_len {
              if filename_len > 1 && buf_idx == filename_len - 1 && filename.as_bytes()[buf_idx] == sep.as_bytes()[0] {
                continue;
              }
              buf[buf_idx] = filename.as_bytes()[buf_idx];
              sav_buf[buf_idx] = filename.as_bytes()[buf_idx] as i8;
              if sav_buf[buf_idx] == 0 {
                break;
              }
            }

            // Create the value of the inner policy representing the path
            let mut inner_value: PolicyValue =
              PolicyValue { path: sav_buf };

            // Convert the value to an array of Bytes
            let inner_value_bytes = plain::as_mut_bytes(&mut inner_value);
            // Take the pointer to the array of Bytes
            let ptr_inner_value: *mut c_void =
              inner_value_bytes.as_mut_ptr() as *mut c_void;

            // Create the inner map key
            let mut inner_key: u64 = hash_string(&buf);
            let ptr_inner_key: *mut c_void =
              &mut inner_key as *mut _ as *mut c_void;

            // If it is the first collision on that value
            if !colliding_paths.contains_key(&(inner_key, i as i32)) {
              // push the previous value in the collision map
              let mut new_set: HashSet<[i8; PATH_SIZE]> = HashSet::new();
              colliding_paths.insert((inner_key, i as i32), new_set);
            }

            // push the colliding value
            match colliding_paths.get_mut(&(inner_key, i as i32)) {
              Some(set) => {
                set.insert(inner_value.path);
              }
              None => (),
            }
          }
        }
        None => (),
      }

      // Recover the file descriptor of the HashMap of collisions
      let coll_map: i32 = skel.maps().policy_map().fd();

      for (key, val) in colliding_paths.iter_mut() {
        let coll_size = val.len();

        //Allocate inner bpf_array
        let mut collision_fd: i32 = bpf_create_map(
          BPF_MAP_TYPE_ARRAY,
          4 as i32,
          PATH_SIZE as i32,
          coll_size as i32,
          0,
        );
        // Create pointer to its file descriptor
        let ptr_collision_map: *mut c_void =
          &mut collision_fd as *mut _ as *mut c_void;

        // Collision array key
        let mut map_key: CollisionKey = CollisionKey {
          hash: key.0,
          policy_num: key.1,
        };

        let ptr_map_key: *mut c_void =
          plain::as_mut_bytes(&mut map_key).as_mut_ptr() as *mut c_void;
        // Insert in collision hash the collision array
        let collision_array_insert_res: i32 = bpf_map_update_elem(
          coll_map,
          ptr_map_key,
          ptr_collision_map,
          BPF_ANY as u64,
        );
        if DEBUG_LOG {
          println!(
            "Insertion of collision array: {}",
            collision_array_insert_res
          );
        }

        // Allocate elements in the collision array
        for coll in val.iter() {
          let ptr_collision_key: *mut c_void =
            &mut idx as *mut _ as *mut c_void;

          let mut collision_value: PolicyValue =
            PolicyValue { path: *coll };
          let ptr_collision_value: *mut c_void =
            plain::as_mut_bytes(&mut collision_value).as_mut_ptr()
              as *mut c_void;
          let collision_insert_res: i32 = bpf_map_update_elem(
            collision_fd,
            ptr_collision_key,
            ptr_collision_value,
            BPF_ANY as u64,
          );
          if DEBUG_LOG {
            println!("Insertion of collision {}", collision_insert_res);
          }
        }

        // Close the file descriptor since the userspace does not further modify this map
        nix::unistd::close(collision_fd)?;
      }
    }
  }
  Ok(())
}

unsafe fn get_collision_num() -> u32 {
  let mut res = 0;
  for i in 0..POLICY_VECTOR.len() {
    let mut seen_hash: HashMap<u64, bool> = HashMap::new();
    let policy = &POLICY_VECTOR[i].deny;
    match policy {
      Some(deny_vec) => {
        for filename in deny_vec.iter() {
          // Convert filename to buffer of bytes
          let mut buf: [u8; PATH_SIZE] = [0; PATH_SIZE];
          for buf_idx in 0..filename.as_bytes().len() {
            buf[buf_idx] = filename.as_bytes()[buf_idx];

            if buf[buf_idx] == 0 {
              break;
            }
          }

          let hash = hash_string(&buf);
          if !seen_hash.contains_key(&hash) {
            seen_hash.insert(hash, false);
            res += 1;
          }
        }
      }
      None => continue,
    }
  }

  res
}

/// This function does the following steps:
/// 1) Writes the needed map sizes
/// 2) Loads the program in the kernel
/// 3) Writes the policy maps in the policy array
/// 4) A never ending loop is started in order to
/// avoid unloading the eBPF program once its skeleton
/// is dropped
fn load_bpf_program(mut open_skel: OpenRestrictorSkel) -> Result<()> {
  let size;
  let mut collision_num;

  unsafe {
    size = POLICY_VECTOR.len();
    collision_num = get_collision_num();
  }

  // write data to eBPF Skel
  open_skel
    .maps_mut()
    .policy_map()
    .set_max_entries(collision_num)?; // Set actual max entries for collision hash
  unsafe {
    open_skel
      .maps_mut()
      .tmp_prefix_hashes()
      .set_max_entries(MAX_DEPTH)?;
  }

  // load the eBPF program in the kernel
  let mut skel = open_skel.load()?;
  let curr_path = std::env::current_exe()?
    .into_os_string()
    .into_string()
    .unwrap();
  let address = get_symbol_address(&curr_path, "attach_policy_num")?;
  let _uprobe = skel
    .progs_mut()
    .attach_policy()
    .attach_uprobe(false, -1, &curr_path, address)?;
  skel.attach()?;

  // policy enforcement
  write_maps(&mut skel)?;

  // drop all the capabilities from the thread
  caps::drop(None, caps::CapSet::Effective, caps::Capability::CAP_BPF)?;
  caps::drop(None, caps::CapSet::Effective, caps::Capability::CAP_PERFMON)?;

  caps::drop(None, caps::CapSet::Permitted, caps::Capability::CAP_BPF)?;
  caps::drop(None, caps::CapSet::Permitted, caps::Capability::CAP_PERFMON)?;

  // set SYNC to true to unlock Deno
  unsafe {
    SYNC = true;
  }

  // Park the thread forever
  // while loop to avoid uncrontrolled unpark()

  unsafe {
    while SYNC {
      std::thread::park();
    }
  }

  Ok(())
}

fn check_capabilities() -> Result<bool> {
  let has_cap_bpf: bool =
    caps::has_cap(None, caps::CapSet::Permitted, caps::Capability::CAP_BPF)?;
  let has_cap_perfmon: bool = caps::has_cap(
    None,
    caps::CapSet::Permitted,
    caps::Capability::CAP_PERFMON,
  )?;

  if !has_cap_bpf || !has_cap_perfmon {
    let mut missing: Vec<String> = vec![];

    if !has_cap_bpf {
      missing.push(String::from("CAP_BPF"));
    }

    if !has_cap_perfmon {
      missing.push(String::from("CAP_PERFMON"));
    }

    let missing_string = missing.join("\n");

    eprintln!("The binary is missing the following capabilities in the permitted set:\n{}\nProhibitions cannot be enforced", missing_string);
    return Ok(false);
  }

  return Ok(true);
}

/// This function does the following steps:
/// 1) Open the eBPF program skeleton
/// 2) Removes the memory limits for bpf programs
/// (usually done in BCC, done by hand in CO-RE)
/// 3) Starts the eBPF loading
/// These steps are done inside a thread that
/// never terminates. Sync between Deno and thread
/// is done through a static boolean.
pub fn enforce_denied_list() -> Result<()> {
  // check if the binary has the needed permitted capabilities
  if !check_capabilities()? {
    return Ok(());
  }

  // Raise capabilities to load bpf program
  caps::raise(None, caps::CapSet::Effective, caps::Capability::CAP_BPF)?;
  caps::raise(None, caps::CapSet::Effective, caps::Capability::CAP_PERFMON)?;

  std::thread::spawn(move || -> Result<()> {
    let skel_builder = RestrictorSkelBuilder::default();

    bump_memlock_rlimit()?;

    let open_skel = skel_builder.open()?;

    load_bpf_program(open_skel)?;

    Ok(())
  });

  // wait for SYNC to be set true
  unsafe {
    while !SYNC {
      continue;
    }
  }

  // Drop all the capabilities from the main process
  caps::drop(None, caps::CapSet::Effective, caps::Capability::CAP_BPF)?;
  caps::drop(None, caps::CapSet::Effective, caps::Capability::CAP_PERFMON)?;

  caps::drop(None, caps::CapSet::Permitted, caps::Capability::CAP_BPF)?;
  caps::drop(None, caps::CapSet::Permitted, caps::Capability::CAP_PERFMON)?;

  Ok(())
}
