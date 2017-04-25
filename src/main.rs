extern crate trust_dns;
extern crate openssl;
extern crate base64;

use trust_dns::rr::domain::Name;
use trust_dns::rr::dns_class::DNSClass;
use trust_dns::rr::record_type::RecordType;
use trust_dns::rr::resource::Record;
use trust_dns::rr::RecordSet;
use trust_dns::rr::record_data::RData;
use trust_dns::rr::dnssec::Signer;
use trust_dns::rr::dnssec::Algorithm;
use trust_dns::rr::dnssec::KeyPair;

use trust_dns::rr::rdata::DNSKEY;

use openssl::pkey::PKey;

use std::net::Ipv4Addr;

fn main() {
    sig_test().unwrap();
}

/// https://tools.ietf.org/html/rfc5702#section-6.1
fn sig_test() -> Result<(),Box<std::error::Error>> {
    /// ```text
    ///    Given a private key with the following values (in Base64):
    ///
    ///    Private-key-format: v1.2
    ///    Algorithm:       8 (RSASHA256)
    ///    Modulus:         wVwaxrHF2CK64aYKRUibLiH30KpPuPBjel7E8ZydQW1HYWHfoGm
    ///                     idzC2RnhwCC293hCzw+TFR2nqn8OVSY5t2Q==
    ///    PublicExponent:  AQAB
    ///    PrivateExponent: UR44xX6zB3eaeyvTRzmskHADrPCmPWnr8dxsNwiDGHzrMKLN+i/
    ///                     HAam+97HxIKVWNDH2ba9Mf1SA8xu9dcHZAQ==
    ///    Prime1:          4c8IvFu1AVXGWeFLLFh5vs7fbdzdC6U82fduE6KkSWk=
    ///    Prime2:          2zZpBE8ZXVnL74QjG4zINlDfH+EOEtjJJ3RtaYDugvE=
    ///    Exponent1:       G2xAPFfK0KGxGANDVNxd1K1c9wOmmJ51mGbzKFFNMFk=
    ///    Exponent2:       GYxP1Pa7CAwtHm8SAGX594qZVofOMhgd6YFCNyeVpKE=
    ///    Coefficient:     icQdNRjlZGPmuJm2TIadubcO8X7V4y07aVhX464tx8Q=
    /// ```

    /// converted from the private key given above with
    /// softhsm2-keyconv --in dnskey --out pemkey
    let pemkey=
r#"-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAwVwaxrHF2CK64aYK
RUibLiH30KpPuPBjel7E8ZydQW1HYWHfoGmidzC2RnhwCC293hCzw+TFR2nqn8OV
SY5t2QIDAQABAkBRHjjFfrMHd5p7K9NHOayQcAOs8KY9aevx3Gw3CIMYfOswos36
L8cBqb73sfEgpVY0MfZtr0x/VIDzG711wdkBAiEA4c8IvFu1AVXGWeFLLFh5vs7f
bdzdC6U82fduE6KkSWkCIQDbNmkETxldWcvvhCMbjMg2UN8f4Q4S2MkndG1pgO6C
8QIgG2xAPFfK0KGxGANDVNxd1K1c9wOmmJ51mGbzKFFNMFkCIBmMT9T2uwgMLR5v
EgBl+feKmVaHzjIYHemBQjcnlaShAiEAicQdNRjlZGPmuJm2TIadubcO8X7V4y07
aVhX464tx8Q=
-----END PRIVATE KEY-----"#;
    let priv_key = PKey::private_key_from_pem(pemkey.as_ref())?;
    let keypair = KeyPair::from_rsa_pkey(priv_key);
    let dnskey = keypair.to_dnskey(Algorithm::RSASHA256)?;

    /// ```text
    ///
    ///    The DNSKEY record for this key would be:
    ///
    ///    example.net.     3600  IN  DNSKEY  (256 3 8 AwEAAcFcGsaxxdgiuuGmCkVI
    ///                     my4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8P
    ///                     kxUdp6p/DlUmObdk= );{id = 9033 (zsk), size = 512b}
    /// ```
    let correct_dnskey = DNSKEY::new(
            true, // zone_key
            false, // secure_entry_point
            false, // revoke
            Algorithm::RSASHA256,
            base64::decode("AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8PkxUdp6p/DlUmObdk=").unwrap()
            );

    // this succeeds, key parsing seems to be fine
    // not comparing the whole RData, as KeyPair::to_dnskey sets secure_entry_point to true
    assert_eq!(dnskey.public_key(), correct_dnskey.public_key());

    let dnskey = correct_dnskey;

    ///    With this key, sign the following RRSet, consisting of 1 A record:
    ///
    ///       www.example.net. 3600  IN  A  192.0.2.91
    
    let mut record = Record::new();
    record.set_name(Name::parse("www.example.net.", None)?)
        .set_rr_type(RecordType::A)
        .set_dns_class(DNSClass::IN)
        .set_ttl(3600)
        .set_rdata(RData::A(Ipv4Addr::new(192, 0, 2, 91)));

    let rrset = RecordSet::from(record);

    println!("Built the following record set: {:?}", rrset);

    let signer = Signer::dnssec_verifier(
        dnskey.clone(),
        dnskey.algorithm().clone(),
        keypair,
        Name::parse("example.net.", None)?,
        true, // is_zone_signing_key
        false, // is_zone_update_auth
        );

    ///    If the inception date is set at 00:00 hours on January 1st, 2000, and
    ///    the expiration date at 00:00 hours on January 1st, 2030, the
    ///    following signature should be created:
    ///
    ///    www.example.net. 3600  IN  RRSIG  (A 8 3 3600 20300101000000
    ///                        20000101000000 9033 example.net. kRCOH6u7l0QGy9qpC9
    ///                        l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEa
    ///                        cFYK/lPtPiVYP4bwg==);{id = 9033}

    let hash = signer.hash_rrset(
                      rrset.name(), //name: &Name,
                      rrset.dns_class(), //dns_class: DNSClass,
                      3, //num_labels: u8,
                      RecordType::A, //type_covered: RecordType,
                      dnskey.algorithm().clone(), //algorithm: Algorithm,
                      3600, //original_ttl: u32,
                      1893456000, //sig_expiration: u32,
                                  // $ TZ=UTC date -d "@1893456000"
                                  // Di 1. Jan 00:00:00 UTC 2030
                      946684800, //sig_inception: u32,
                                 // $ TZ=UTC date -d "@946684800"
                                 // Sa 1. Jan 00:00:00 UTC 2000
                      signer.calculate_key_tag()?, //key_tag: u16,
                      signer.signer_name(), //signer_name: &Name,
                      &rrset.clone().into_iter().collect::<Vec<Record>>()[..], //records: &[Record])
    )?;
    let sig = signer.sign(&hash)?;
    println!("Calculated signature: {:?}", sig);

    // compare with example value from RFC 5702
    assert_eq!(sig, base64::decode("kRCOH6u7l0QGy9qpC9l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEacFYK/lPtPiVYP4bwg==")?);

    Ok(())
}
