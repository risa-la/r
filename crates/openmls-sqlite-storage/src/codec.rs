use serde::Serialize;

pub trait Codec: Default {
    type Error: std::error::Error + std::fmt::Debug + Send + Sync + 'static;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error>;
    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error>;
}

/// MessagePack, with struct fields by name.
///
/// The format has to describe itself: OpenMLS reads some of its types
/// through `#[serde(untagged)]`, which formats such as postcard cannot
/// decode. Field names let a later OpenMLS read state that an earlier one
/// wrote, when it adds fields with `#[serde(default)]`.
#[derive(Debug, Default)]
pub struct MsgPack;

/// A [`MsgPack`] encoding or decoding error.
#[derive(Debug, thiserror::Error)]
pub enum MsgPackError {
    #[error(transparent)]
    Encode(#[from] rmp_serde::encode::Error),
    #[error(transparent)]
    Decode(#[from] rmp_serde::decode::Error),
}

impl Codec for MsgPack {
    type Error = MsgPackError;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        Ok(rmp_serde::to_vec_named(value)?)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        Ok(rmp_serde::from_slice(slice)?)
    }
}
