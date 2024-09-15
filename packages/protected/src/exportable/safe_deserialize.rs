use serde::Deserializer;

pub trait SafeDeserialize<'de>: Sized {
    fn safe_deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>;
}
