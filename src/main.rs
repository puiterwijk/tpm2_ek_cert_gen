use anyhow::{Context as ah_Context, Result};
use std::str::FromStr;

use tss_esapi::{constants::algorithm::AsymmetricAlgorithm, Context, Tcti};

use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    hash::MessageDigest,
    pkey::{HasPublic, PKey, PKeyRef, Private, Public},
    rsa::Rsa,
    x509::{X509NameBuilder, X509NameRef, X509},
};

fn get_ek_pubkey() -> Result<Rsa<Public>> {
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

    Rsa::from_public_components(modulus, exponent).context("Error building pubkey")
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

fn main() -> Result<()> {
    let ek_pubkey = get_ek_pubkey().context("Error getting EK pubkey")?;
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
    let ek_cert = ek_cert.to_pem().context("Error building PEM of ek_cert")?;
    let ek_cert = String::from_utf8(ek_cert).context("Error parsing ek_cert as utf8")?;

    println!("CA cert: ");
    println!("{}", ca_cert);

    println!("EK cert: ");
    println!("{}", ek_cert);

    Ok(())
}
