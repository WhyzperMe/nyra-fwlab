//! Admission limits applied before allocating untrusted export collections.
use nyra_fw_core::{FwError, Result};
use serde::{
    Deserialize,
    de::{self, DeserializeOwned, DeserializeSeed, SeqAccess, Visitor},
};
use std::fmt;

pub(crate) const MAX_EXPORT_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_FUNCTIONS: usize = 20_000;
pub(crate) const MAX_EDGES: usize = 30_000;
pub(crate) const MAX_DECOMPILED: usize = 120;

pub(crate) fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() > MAX_EXPORT_BYTES {
        return Err(FwError::Limit("Ghidra export exceeds 64 MiB".into()));
    }
    Ok(serde_json::from_slice(bytes)?)
}

pub(crate) fn functions<'de, D, T>(deserializer: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: de::Deserializer<'de>,
    T: Deserialize<'de>,
{
    bounded::<D, T, MAX_FUNCTIONS>(deserializer)
}

pub(crate) fn edges<'de, D, T>(deserializer: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: de::Deserializer<'de>,
    T: Deserialize<'de>,
{
    bounded::<D, T, MAX_EDGES>(deserializer)
}

pub(crate) fn decompiled<'de, D, T>(deserializer: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: de::Deserializer<'de>,
    T: Deserialize<'de>,
{
    bounded::<D, T, MAX_DECOMPILED>(deserializer)
}

fn bounded<'de, D, T, const MAX: usize>(deserializer: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: de::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Items<T, const MAX: usize>(std::marker::PhantomData<T>);
    struct RejectExtra;
    impl<'de> DeserializeSeed<'de> for RejectExtra {
        type Value = ();
        fn deserialize<D: de::Deserializer<'de>>(self, _: D) -> std::result::Result<(), D::Error> {
            Err(de::Error::custom(
                "Ghidra export collection exceeds its entry limit",
            ))
        }
    }
    impl<'de, T: Deserialize<'de>, const MAX: usize> Visitor<'de> for Items<T, MAX> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "at most {MAX} Ghidra export entries")
        }
        fn visit_seq<A: SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> std::result::Result<Vec<T>, A::Error> {
            let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX));
            while values.len() < MAX {
                let Some(value) = sequence.next_element()? else {
                    return Ok(values);
                };
                values.push(value);
            }
            // Determine whether another item exists without decoding or allocating it.
            sequence.next_element_seed(RejectExtra)?;
            Ok(values)
        }
    }
    deserializer.deserialize_seq(Items::<T, MAX>(std::marker::PhantomData))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize)]
    struct One {
        #[serde(deserialize_with = "one")]
        items: Vec<u64>,
    }
    fn one<'de, D: de::Deserializer<'de>>(d: D) -> std::result::Result<Vec<u64>, D::Error> {
        bounded::<D, u64, 1>(d)
    }

    #[test]
    fn rejects_an_extra_entry_before_decoding_its_payload() {
        assert_eq!(
            serde_json::from_str::<One>(r#"{"items":[1]}"#)
                .unwrap()
                .items,
            [1]
        );
        let error = serde_json::from_str::<One>(r#"{"items":[1,{"unparsed": "#).unwrap_err();
        assert!(error.is_data());
        assert!(error.to_string().contains("entry limit"));
    }

    #[test]
    fn rejects_oversized_input_before_json_parsing() {
        let bytes = vec![b'!'; MAX_EXPORT_BYTES + 1];
        assert!(matches!(
            parse::<serde_json::Value>(&bytes),
            Err(FwError::Limit(_))
        ));
    }
}
