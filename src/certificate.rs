use chrono::DateTime;
use data_encoding::HEXLOWER;
use nu_protocol::{Record, Span, Value};
use schannel::{
    cert_context::{CertContext, HashAlgorithm},
    cert_store::PfxImportOptions,
};
use x509_parser::{
    certificate::X509Certificate, error::X509Error, extensions::GeneralName, pem::Pem,
    prelude::FromDer, x509::X509Name,
};

use crate::error::CerError;

type CerResult<T> = Result<T, CerError>;

pub fn get_pfx_values(data: &[u8], password: Option<Value>, span: Span) -> CerResult<Vec<Value>> {
    let mut pfx = PfxImportOptions::new();
    pfx.no_persist_key(true);
    pfx.include_extended_properties(true);
    if let Some(password) = password {
        let password = password.as_str().map_err(CerError::Password)?;
        pfx.password(password);
    }
    let store = pfx.import(data).map_err(CerError::Pfx)?;
    let values = store
        .certs()
        .map(|cer| {
            let der = cer.to_der();
            let (_rem, pem) =
                x509_parser::certificate::X509Certificate::from_der(der).map_err(CerError::Der)?;
            let mut record = get_record(&pem, span)?;
            record.push(
                "friendly",
                Value::string(get_pfx_friendly_name(&cer)?, span),
            );
            record.push("thumbprint", Value::string(get_pfx_thumbprint(&cer)?, span));
            let value = Value::record(record, span);
            Ok(value)
        })
        .collect::<Result<Vec<Value>, CerError>>()?;
    Ok(values)
}

pub fn get_pem_values(val: &String, span: Span) -> CerResult<Vec<Value>> {
    Pem::iter_from_buffer(val.as_bytes())
        .map(|pem| {
            let pem = pem.map_err(CerError::Pem)?;
            let cer = pem.parse_x509().map_err(CerError::Parse)?;
            let mut record = get_record(&cer, span)?;
            record.push("thumbprint", get_thumbprint(&pem, span));
            let value = Value::record(record, span);
            Ok(value)
        })
        .collect::<Result<Vec<Value>, CerError>>()
}

pub fn get_record(cer: &X509Certificate, span: Span) -> CerResult<Record> {
    let mut record = Record::new();
    record.push("cn", get_common_names(cer, span)?);
    record.push("subject", get_subject(cer, span));
    record.push("san", get_sans(cer, span)?);
    record.push("ca", get_ca_common_names(cer, span)?);
    record.push("ca_subject", get_ca_subject(cer, span));
    record.push("expiration", get_expiration(cer, span)?);
    Ok(record)
}

pub fn get_thumbprint(pem: &Pem, span: Span) -> Value {
    let contents = &pem.contents;
    let val = sha1_smol::Sha1::from(contents).hexdigest();
    Value::string(val, span)
}

pub fn get_subject(cer: &X509Certificate, span: Span) -> Value {
    let val = cer.subject().to_string();
    Value::string(val, span)
}

pub fn get_ca_subject(cer: &X509Certificate, span: Span) -> Value {
    let val = cer.issuer().to_string();
    Value::string(val, span)
}

pub fn get_expiration(cer: &X509Certificate, span: Span) -> CerResult<Value> {
    let validity = cer.validity().not_after;
    let timestamp = validity.timestamp();
    let expiration = DateTime::from_timestamp(timestamp, 0)
        .map(|datetime| datetime.into())
        .ok_or(CerError::Timestamp)?;
    let value = Value::date(expiration, span);
    Ok(value)
}

pub fn get_common_names(cer: &X509Certificate, span: Span) -> CerResult<Value> {
    let subject = cer.tbs_certificate.subject();
    parse_common_names(subject, span)
}

pub fn get_ca_common_names(cer: &X509Certificate, span: Span) -> CerResult<Value> {
    let issuer = cer.issuer();
    parse_common_names(issuer, span)
}

pub fn parse_common_names(name: &X509Name, span: Span) -> CerResult<Value> {
    let common_names = name
        .iter_common_name()
        .map(|cn| {
            // Only NumericString, PrintableString, UTF8String and IA5String are considered here
            let cn = match cn.as_str() {
                Ok(as_str) => as_str,
                // Other string types can be read using as_slice
                Err(_err) => {
                    let slice = cn.as_slice();
                    std::str::from_utf8(slice).map_err(CerError::CommonName)?
                }
            };
            Ok(Value::string(cn.to_string(), span))
        })
        .collect::<Result<Vec<Value>, CerError>>()?;
    let list = Value::list(common_names, span);
    Ok(list)
}

pub fn get_sans(cer: &X509Certificate, span: Span) -> CerResult<Value> {
    let sans = match cer
        .subject_alternative_name()
        .map_err(CerError::San)? // the Subject Alternative Name extension is invalid, or is present twice or more
    {
        Some(sans) => sans
            .value
            .general_names
            .iter()
            .map(|name| {
                match name {
                    GeneralName::DNSName(name) => Ok(Value::string(name.to_string(), span)),
                    _ => Err(CerError::San(X509Error::InvalidCertificate)), // we only handle DNS names
                }
            })
            .collect::<CerResult<Vec<Value>>>()?,
        None => Vec::new(), // no Subject Alternative Name extension was found in the certificate
    };
    let list = Value::list(sans, span);
    Ok(list)
}

pub fn get_pfx_friendly_name(cer: &CertContext) -> CerResult<String> {
    cer.friendly_name().map_err(CerError::FriendlyName)
}

pub fn get_pfx_thumbprint(cer: &CertContext) -> CerResult<String> {
    let thumbprint = cer
        .fingerprint(HashAlgorithm::sha1())
        .map_err(CerError::Fingerprint)?;
    Ok(HEXLOWER.encode(&thumbprint))
}
