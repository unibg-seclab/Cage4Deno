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

use anyhow::bail;
use landlock::{
  make_bitflags, Access, AccessFs, BitFlags, PathBeneath, PathFd, PathFdError,
  Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError, RulesetStatus, ABI,
};
use std::fmt;
use thiserror::Error;

use crate::bpf::enforcer::attach_policy_num;
use crate::policy::POLICY_VECTOR;

const ACCESS_FS_ROUGHLY_READ: BitFlags<AccessFs> = make_bitflags!(AccessFs::{
    ReadFile | ReadDir});

const ACCESS_FS_ROUGHLY_WRITE: BitFlags<AccessFs> = make_bitflags!(AccessFs::{
    WriteFile | RemoveDir | RemoveFile | MakeChar | MakeDir | MakeReg | MakeSock | MakeFifo |
        MakeBlock | MakeSym
});

const ACCESS_FS_EXEC: BitFlags<AccessFs> = make_bitflags!(AccessFs::{
    Execute});

#[derive(Error)]
enum PathStringError {
  PathFdErr(PathFdError),
  RulesetErr(RulesetError),
}

impl From<PathFdError> for PathStringError {
  fn from(error: PathFdError) -> Self {
    PathStringError::PathFdErr(error)
  }
}

impl From<RulesetError> for PathStringError {
  fn from(error: RulesetError) -> Self {
    PathStringError::RulesetErr(error)
  }
}

impl fmt::Debug for PathStringError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{:?}", self)
  }
}

impl fmt::Display for PathStringError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{:?}", self)
  }
}

fn iter_from_string(
  path_opt: &Option<Vec<String>>,
  access: BitFlags<AccessFs>,
) -> Vec<Result<PathBeneath<PathFd>, PathStringError>> {
  match path_opt {
    Some(path) => {
      let is_empty = path.is_empty();
      path
        .iter()
        .skip_while(|_| is_empty)
        .map(|path| {
          Ok(PathBeneath::new(PathFd::new(path).unwrap(), access))
        })
        .collect()
    }
    None => vec![],
  }
}

pub fn sandboxer(policy_idx: Option<u32>) -> Result<(), anyhow::Error> {
  match policy_idx {
    Some(idx) => {
      unsafe {
        let read = &POLICY_VECTOR[idx as usize].read;
        let write = &POLICY_VECTOR[idx as usize].write;
        let exec = &POLICY_VECTOR[idx as usize].exec;
        let status = Ruleset::new()
          .handle_access(AccessFs::from_all(ABI::V1))?
          .create()?
          .add_rules(iter_from_string(&read, ACCESS_FS_ROUGHLY_READ))?
          .add_rules(iter_from_string(&write, ACCESS_FS_ROUGHLY_WRITE))?
          .add_rules(iter_from_string(&exec, ACCESS_FS_EXEC))?
          .restrict_self()
          .expect("Failed to enforce ruleset");

        if status.ruleset == RulesetStatus::NotEnforced {
          bail!("Landlock is not supported by the running kernel.");
        }
      }
      attach_policy_num(idx);
    }
    None => (),
  }
  Ok(())
}
