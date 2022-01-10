use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::cmp::{Eq, PartialEq};
use std::fmt::Display;
use std::hash::Hash;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AddressError {
  #[error("Expected length between 26 and 34, found: {0}")]
  InvalidLength(usize),
  #[error("Expected the first character to be '1', found: {0}")]
  InvalidStartingCharacter(char),
}

#[derive(Hash, PartialEq, Eq, Debug, Clone)]
pub struct Address(pub String);

impl Address {
  // Returns the digest of the SHA256 hash of the ASCII encoding
  pub fn get_address_hash(&self) -> Vec<u8> {
    let mut hasher = Sha256::default();
    hasher.update(&self.0);
    hasher.finalize().to_vec()
  }

  // Returns the digest of the SHA1 hash of the ACII encoding
  pub fn get_address_sha1(&self) -> String {
    self.0.clone()
  }

  // Returns the first 6 and last 4 characters of address
  pub fn get_address_short(&self) -> String {
    if self.0.as_str() == "Test" {
      return self.0.clone();
    }
    let l = self.0.len();
    let f = self.0.get(0..6).unwrap();
    let b = self.0.get(l - 5..l).unwrap();
    format!("{}...{}", f, b)
  }
}

impl Display for Address {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.0)
  }
}

impl Serialize for Address {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    serializer.serialize_str(&self.0)
  }
}

struct AddressVisitor;

impl<'de> Visitor<'de> for AddressVisitor {
  type Value = Address;

  fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
    formatter.write_str("a string between 26 and 34 characters starting with a '1'")
  }

  fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
  where
    E: serde::de::Error,
  {
    if v.len() > 34 || v.len() < 26 {
      return Err(E::custom("Expected length between 26 and 34 characters"));
    }
    if !v.starts_with('1') {
      return Err(E::custom("Address should start with '1'"));
    }
    Address::from_str(v).map_err(|_| E::custom("invalid ZeroNet address"))
  }
}

impl<'de> Deserialize<'de> for Address {
  fn deserialize<D>(deserializer: D) -> Result<Address, D::Error>
  where
    D: Deserializer<'de>,
  {
    deserializer.deserialize_str(AddressVisitor)
  }
}

impl FromStr for Address {
  type Err = AddressError;

  fn from_str(string: &str) -> Result<Address, AddressError> {
    let s = String::from(string);

    // "Test" is the only address invalid address allowed
    if string == "Test" {
      return Ok(Address(String::from(string)));
    }

    if s.len() > 34 || s.len() < 26 {
      return Err(AddressError::InvalidLength(s.len()));
    }

    if !s.starts_with('1') {
      return Err(AddressError::InvalidStartingCharacter(
        s.chars()
          .next()
          .expect("string length to have been asserted earlier"),
      ));
    }

    Ok(Address(String::from(string)))
  }
}

impl Into<String> for Address {
  fn into(self) -> String {
    self.0.clone()
  }
}

#[cfg(test)]
#[cfg_attr(tarpaulin, ignore)]
mod tests {
  use super::*;

  #[test]
  fn test_from_str_test_address() {
    let result = Address::from_str("Test");
    assert!(result.is_ok());
  }

  #[test]
  fn test_from_str() {
    let result = Address::from_str("1HeLLo4uzjaLetFx6NH3PMwFP3qbRbTf3D");
    assert!(result.is_ok());
  }

  #[test]
  fn test_serialization() {
    let address = Address("1HeLLo4uzjaLetFx6NH3PMwFP3qbRbTf3D".to_string());
    let result = serde_json::to_string(&address);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "\"1HeLLo4uzjaLetFx6NH3PMwFP3qbRbTf3D\"");
  }

  #[test]
  fn test_deserialization() {
    let result = serde_json::from_str("\"1HeLLo4uzjaLetFx6NH3PMwFP3qbRbTf3D\"");
    assert!(result.is_ok(), "Encountered error: {:?}", result);
    let address: Address = result.unwrap();
    assert_eq!(
      address,
      Address("1HeLLo4uzjaLetFx6NH3PMwFP3qbRbTf3D".to_string())
    );
  }

  #[test]
  fn test_sha1() {
    let address = Address("1HeLLo4uzjaLetFx6NH3PMwFP3qbRbTf3D".to_string());
    assert_eq!(
      address.get_address_sha1(),
      "1HeLLo4uzjaLetFx6NH3PMwFP3qbRbTf3D".to_string()
    );
  }
}
