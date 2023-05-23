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

use serde::{Deserialize, Serialize};

use std::error::Error;
use std::fmt;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::BufReader;
use std::path::Path;

pub static mut POLICY_VECTOR: Vec<PolicyVectors> = vec![];
pub static mut MAX_DEPTH: u32 = 1;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Policy {
  pub policy_name: String,
  pub kernel_id: Option<u32>,
  pub read: Option<Vec<String>>,
  pub write: Option<Vec<String>>,
  pub exec: Option<Vec<String>>,
  pub deny: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct PolicyIdentifiers {
  pub policy_name: String,
  pub kernel_id: Option<u32>,
}

pub struct PolicyVectors {
  pub read: Option<Vec<String>>,
  pub write: Option<Vec<String>>,
  pub exec: Option<Vec<String>>,
  pub deny: Option<Vec<String>>,
}

/// Only the id of the policy is necessary
/// identify the structure
impl Hash for Policy {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.policy_name.hash(state);
  }
}

impl PartialEq for Policy {
  fn eq(&self, other: &Self) -> bool {
    self.policy_name == other.policy_name
  }
}

impl Eq for Policy {}

impl fmt::Display for Policy {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(
      f,
      "Policy name: {}
                   \nKernel_id: {:?}
                   \nRead: {:?}
                   \nWrite: {:?}
                   \nExec: {:?}
                   \nDeny: {:?}",
      self.policy_name,
      self.kernel_id,
      self.read,
      self.write,
      self.exec,
      self.deny
    )
  }
}

impl Default for Policy {
  fn default() -> Self {
    Policy {
      policy_name: String::new(),
      kernel_id: None,
      read: Some(vec![]),
      write: Some(vec![]),
      exec: Some(vec![]),
      deny: Some(vec![]),
    }
  }
}

impl From<Policy> for PolicyVectors {
  fn from(policy: Policy) -> PolicyVectors {
    PolicyVectors {
      read: policy.read,
      write: policy.write,
      exec: policy.exec,
      deny: policy.deny,
    }
  }
}

impl Hash for PolicyIdentifiers {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.policy_name.hash(state);
  }
}

impl Default for PolicyIdentifiers {
  fn default() -> Self {
    PolicyIdentifiers {
      policy_name: String::new(),
      kernel_id: None,
    }
  }
}

impl PartialEq for PolicyIdentifiers {
  fn eq(&self, other: &Self) -> bool {
    self.policy_name == other.policy_name
  }
}

impl Eq for PolicyIdentifiers {}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct PolicyVec {
  pub policies: Vec<Policy>,
  pub max_depth: u32,
}

pub fn read_policy_from_file<P: AsRef<Path>>(
  path: P,
) -> Result<PolicyVec, Box<dyn Error>> {
  // Open the file in read-only mode with buffer.
  let file = File::open(path)?;
  let reader = BufReader::new(file);

  // Read the JSON contents of the file as an instance of 'PolicyVec'
  let policy_vec = serde_json::from_reader(reader)?;

  // Return the `PolicyVec`
  Ok(policy_vec)
}
