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

pub struct Djb2 {
  state: u64,
}

impl Default for Djb2 {
  fn default() -> Djb2 {
    Djb2 { state: 5381 }
  }
}

impl Djb2 {
  pub fn finish(&self) -> u64 {
    self.state
  }

  pub fn write(&mut self, bytes: &[u8]) {
    for &b in bytes {
      if b == 0 {
        break;
      }
      self.state = (self.state << 5)
        .wrapping_add(self.state)
        .wrapping_add(b as u64);
    }
  }
}
