use anyhow::{Context as ah_Context, Result};
use std::{convert::TryFrom, env, str::FromStr};

use tss_esapi::{
    constants::{
        algorithm::{AsymmetricAlgorithm, Cipher, HashingAlgorithm},
        tags::PropertyTag,
        types::session::SessionType,
    },
    handles::{AuthHandle, NvIndexHandle, NvIndexTpmHandle},
    interface_types::resource_handles::NvAuth,
    nv::storage::{NvIndexAttributes, NvPublicBuilder},
    structures::MaxNvBuffer,
    utils::TpmaSessionBuilder,
    Context, Tcti,
};

use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    hash::MessageDigest,
    pkey::{HasPublic, PKey, PKeyRef, Private, Public},
    rsa::Rsa,
    x509::{X509NameBuilder, X509NameRef, X509},
};

fn get_ek_pubkey() -> Result<(Rsa<Public>, Context)> {
    let tcti = Tcti::from_str("tabrmd:").context("Error building tcti")?;
    let mut ctx = unsafe { Context::new(tcti) }.context("Error initiating context")?;

    let ek_handle =
        tss_esapi::abstraction::ek::create_ek_object(&mut ctx, AsymmetricAlgorithm::Rsa)
            .context("Error getting EK object")?;
    let (ek_pub, _, _) = ctx
        .read_public(ek_handle)
        .context("Error getting EK public")?;

    let mut exponent = unsafe { ek_pub.publicArea.parameters.rsaDetail.exponent };
    if exponent == 0 {
        exponent = 65537;
    }
    let exponent = BigNum::from_u32(exponent).context("Error building exponent bignum")?;

    let pubkey_size = unsafe { ek_pub.publicArea.unique.rsa.size };
    let mut modulus = unsafe { ek_pub.publicArea.unique.rsa.buffer }.to_vec();
    modulus.resize(pubkey_size as usize, 254);
    let modulus = BigNum::from_slice(&modulus).context("Error building modulus bignum")?;

    let pubkey = Rsa::from_public_components(modulus, exponent).context("Error building pubkey")?;

    Ok((pubkey, ctx))
}

fn generate_ca_key() -> Result<Rsa<Private>> {
    Rsa::generate(2048).context("Error generating new RSA key")
}

fn generate_signed_certificate<T>(
    privkey: &PKeyRef<Private>,
    pubkey: &PKeyRef<T>,
    issuer_name: &X509NameRef,
    subject_name: &X509NameRef,
    serial_number: Asn1Integer,
) -> Result<X509>
where
    T: HasPublic,
{
    let mut cert = X509::builder().context("Error building X509 builder")?;

    cert.set_not_after(
        Asn1Time::days_from_now(365)
            .context("Error building not-after time")?
            .as_ref(),
    )
    .context("Error setting not-after")?;

    cert.set_not_before(
        Asn1Time::days_from_now(0)
            .context("Error building not-before time")?
            .as_ref(),
    )
    .context("Error setting not-before")?;

    cert.set_version(2).context("Error setting version")?;

    cert.set_serial_number(serial_number.as_ref())
        .context("Error setting serial number")?;

    cert.set_issuer_name(issuer_name)
        .context("Error setting issuer name")?;

    cert.set_subject_name(subject_name)
        .context("Error setting subject name")?;

    cert.set_pubkey(pubkey).context("Error setting pubkey")?;

    // Sign it
    cert.sign(privkey, MessageDigest::sha256())
        .context("Error signing certificate")?;

    // And return! That was a thing
    Ok(cert.build())
}

fn write_full(ctx: &mut Context, index_handle: NvIndexHandle, data: &[u8]) -> Result<()> {
    let maxsize = ctx
        .get_tpm_property(PropertyTag::NvBufferMax)?
        .unwrap_or(512) as usize;

    let datalen = data.len() as usize;

    for offset in (0..datalen).step_by(maxsize) {
        let size = std::cmp::min(maxsize, datalen) as usize;

        let mut buf = Vec::with_capacity(maxsize);
        buf.extend_from_slice(&data[offset..size]);
        let buf =
            MaxNvBuffer::try_from(buf).context("Error building maxnvbuffer from data part")?;

        ctx.nv_write(AuthHandle::Owner, index_handle, &buf, offset as u16)
            .context("Error writing part of NV buffer")?;
    }

    Ok(())
}

const RSA_2048_NV_INDEX: u32 = 0x01c00002;
fn insert_ek_cert_into_tpm(ctx: &mut Context, pubcert: &[u8]) -> Result<()> {
    let session = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            Cipher::aes_128_cfb(),
            HashingAlgorithm::Sha256,
        )
        .context("Error starting new session")?;
    let session_attr = TpmaSessionBuilder::new().build();
    ctx.tr_sess_set_attributes(session.unwrap(), session_attr)
        .context("Error setting session attributes")?;

    // Create owner nv public.
    let mut idx_attrs = NvIndexAttributes(0);
    idx_attrs.set_owner_write(true);
    idx_attrs.set_owner_read(true);

    let nv_pub = NvPublicBuilder::new()
        .with_nv_index(
            NvIndexTpmHandle::new(RSA_2048_NV_INDEX)
                .context("Error building nv index tpm handle")?,
        )
        .with_index_name_algorithm(HashingAlgorithm::Sha256)
        .with_index_attributes(idx_attrs)
        .with_data_area_size(pubcert.len())
        .build()
        .unwrap();

    ctx.execute_with_session(session, |ctx| {
        let idxhandle = ctx
            .nv_define_space(NvAuth::Platform, None, &nv_pub)
            .context("Error defining NV space")?;

        write_full(ctx, idxhandle, pubcert).context("Error writing contents to NV Index")
    })
    .context("Error executing TPM write commands")
}

fn main() -> Result<()> {
    let mut args = env::args();
    // Ignore first argument (that's our name)
    args.next();

    // Get data
    let (ek_pubkey, ctx) = get_ek_pubkey().context("Error getting EK pubkey")?;
    let ek_pubkey = PKey::from_rsa(ek_pubkey).context("Error building pkey from ek pubkey")?;
    let ek_pubkey = ek_pubkey.as_ref();
    let ca_privkey = generate_ca_key().context("Error generating CA key")?;
    let ca_privkey = PKey::from_rsa(ca_privkey).context("Error building pkey from ca privkey")?;
    let ca_privkey = ca_privkey.as_ref();

    let mut ca_name = X509NameBuilder::new().context("Error building empty caname")?;
    ca_name
        .append_entry_by_text("C", "NL")
        .context("Error setting CA C")?;
    ca_name
        .append_entry_by_text("O", "NOT my lazy TPM vendor....")
        .context("Error setting CA O")?;
    ca_name
        .append_entry_by_text("CN", "My TPMs EK CA")
        .context("Error setting CA CN")?;
    let ca_name = ca_name.build();
    let ca_name = ca_name.as_ref();

    let mut ek_name = X509NameBuilder::new().context("Error building empty ek-name")?;
    ek_name
        .append_entry_by_text("C", "US")
        .context("Error setting ek C")?;
    ek_name
        .append_entry_by_text("O", "Maybe someone who cares?")
        .context("Error setting ek O")?;
    ek_name
        .append_entry_by_text("CN", "My TPMs Endorsement Key Certificate. YAY")
        .context("Error setting ek CN")?;
    let ek_name = ek_name.build();
    let ek_name = ek_name.as_ref();

    let ca_cert = generate_signed_certificate(
        &ca_privkey,
        &ca_privkey,
        &ca_name,
        &ca_name,
        Asn1Integer::from_bn(
            BigNum::from_u32(1)
                .context("Error building serial bignum")?
                .as_ref(),
        )
        .context("Error building Asn1Integer")?,
    )
    .context("Error building CA Certificate")?;
    let ca_cert = ca_cert.to_pem().context("Error building PEM of ca_cert")?;
    let ca_cert = String::from_utf8(ca_cert).context("Error parsing ca_cert as utf8")?;

    let ek_cert = generate_signed_certificate(
        &ca_privkey,
        &ek_pubkey,
        &ca_name,
        &ek_name,
        Asn1Integer::from_bn(
            BigNum::from_u32(2)
                .context("Error building serial bignum")?
                .as_ref(),
        )
        .context("Error building Asn1Integer")?,
    )
    .context("Error building CA Certificate")?;
    let ek_cert_pem = ek_cert.to_pem().context("Error building PEM of ek_cert")?;
    let ek_cert_pem = String::from_utf8(ek_cert_pem).context("Error parsing ek_cert as utf8")?;
    let ek_cert_der = ek_cert.to_der().context("Error building DER of ek_cert")?;

    println!("CA cert: ");
    println!("{}", ca_cert);

    println!("EK cert: ");
    println!("{}", &ek_cert_pem);

    if let Some(arg) = args.next() {
        if arg == "insert_into_tpm" {
            let mut ctx = ctx;
            insert_ek_cert_into_tpm(&mut ctx, &ek_cert_der)
                .context("Error inserting EK cert into TPM")?;
        }
    }

    Ok(())
}
