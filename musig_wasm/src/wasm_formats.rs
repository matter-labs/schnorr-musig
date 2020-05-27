use bellman::pairing::bn256::Bn256;
use bellman::pairing::ff::{PrimeField, PrimeFieldRepr};
use franklin_crypto::alt_babyjubjub::edwards::Point;
use franklin_crypto::alt_babyjubjub::fs::{Fs, FsRepr};
use franklin_crypto::alt_babyjubjub::AltJubjubBn256;
use franklin_crypto::alt_babyjubjub::Unknown;
use franklin_crypto::eddsa::{PrivateKey, PublicKey};
use musig::musig_error::MusigError;
use wasm_bindgen::prelude::*;

pub(crate) struct WasmFormats {}

impl WasmFormats {
    /// Fs
    fn read_fs(reader: &[u8], be: bool) -> Result<Fs, JsValue> {
        let mut fs_repr = FsRepr::default();

        let res = if be {
            fs_repr.read_be(reader)
        } else {
            fs_repr.read_le(reader)
        };

        res.map_err(WasmFormats::map_error_to_js)?;

        Fs::from_repr(fs_repr).map_err(WasmFormats::map_error_to_js)
    }

    fn read_fs_be(reader: &[u8]) -> Result<Fs, JsValue> {
        WasmFormats::read_fs(reader, true)
    }

    pub(crate) fn read_fs_le(reader: &[u8]) -> Result<Fs, JsValue> {
        WasmFormats::read_fs(reader, false)
    }

    fn write_fs<W: std::io::Write>(fs: &Fs, be: bool, writer: W) -> Result<(), JsValue> {
        let repr = fs.into_repr();

        let res = if be {
            repr.write_be(writer)
        } else {
            repr.write_le(writer)
        };

        res.map_err(WasmFormats::map_error_to_js)
    }

    fn write_fs_be<W: std::io::Write>(fs: &Fs, writer: W) -> Result<(), JsValue> {
        WasmFormats::write_fs(fs, true, writer)
    }

    pub(crate) fn write_fs_le<W: std::io::Write>(fs: &Fs, writer: W) -> Result<(), JsValue> {
        WasmFormats::write_fs(fs, false, writer)
    }

    /// Private keys
    pub(crate) fn read_private_key(reader: &[u8]) -> Result<PrivateKey<Bn256>, JsValue> {
        let fs = WasmFormats::read_fs_be(reader)?;

        Ok(PrivateKey::<Bn256>(fs))
    }

    pub(crate) fn write_private_key<W: std::io::Write>(
        private_key: &PrivateKey<Bn256>,
        writer: W,
    ) -> Result<(), JsValue> {
        WasmFormats::write_fs_be(&private_key.0, writer)
    }

    /// Public keys
    pub(crate) fn read_public_key(
        reader: &[u8],
        params: &AltJubjubBn256,
    ) -> Result<PublicKey<Bn256>, JsValue> {
        let point = WasmFormats::read_point(reader, params)?;

        Ok(PublicKey::<Bn256>(point))
    }

    pub(crate) fn write_public_key<W: std::io::Write>(
        public_key: &PublicKey<Bn256>,
        writer: W,
    ) -> Result<(), JsValue> {
        WasmFormats::write_point(&public_key.0, writer)
    }

    /// Points
    pub(crate) fn read_point(
        reader: &[u8],
        params: &AltJubjubBn256,
    ) -> Result<Point<Bn256, Unknown>, JsValue> {
        let p =
            Point::<Bn256, Unknown>::read(reader, params).map_err(WasmFormats::map_error_to_js)?;

        // this one is for a simple sanity check. In application purposes the pk will always be in a right group
        let order_check_pk = p.mul(Fs::char(), params);
        if !order_check_pk.eq(&Point::zero()) {
            return Err(JsValue::from("Invalid point"));
        }

        Ok(p)
    }

    pub(crate) fn write_point<W: std::io::Write>(
        point: &Point<Bn256, Unknown>,
        writer: W,
    ) -> Result<(), JsValue> {
        point.write(writer).map_err(WasmFormats::map_error_to_js)
    }

    /// Errors
    pub(crate) fn map_error_to_js(err: impl std::error::Error) -> JsValue {
        JsValue::from(err.to_string())
    }

    pub(crate) fn map_musig_error_to_js(err: MusigError) -> JsValue {
        JsValue::from(err.description())
    }
}

#[cfg(test)]
mod wasm_formats_unit_tests {
    use crate::utils::Utils;
    use crate::wasm_formats::WasmFormats;
    use franklin_crypto::alt_babyjubjub::AltJubjubBn256;

    #[test]
    fn read_write() {
        let seed = [1usize; 8];
        let params = AltJubjubBn256::new();

        let sk_data = Utils::generate_private_key(&seed).expect("");

        let sk = WasmFormats::read_private_key(&sk_data[..]).expect("");

        let mut sk_data2 = Vec::<u8>::new();

        WasmFormats::write_private_key(&sk, &mut sk_data2).expect("");

        assert_eq!(sk_data, sk_data2);

        let pk_data = Utils::extract_public_key(&sk_data).expect("");

        let pk = WasmFormats::read_public_key(&pk_data[..], &params).expect("");

        let mut pk_data2 = Vec::<u8>::new();

        WasmFormats::write_public_key(&pk, &mut pk_data2).expect("");

        assert_eq!(pk_data, pk_data2);
    }
}
