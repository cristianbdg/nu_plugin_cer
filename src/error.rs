use nu_protocol::{LabeledError, ShellError};
use std::str::Utf8Error;
use thiserror::Error;
use x509_parser::{
    error::{PEMError, X509Error},
    nom::Err as NomErr,
};

#[derive(Error, Debug)]
pub enum CerError {
    #[error("cannot read certificate")]
    Pem(#[source] PEMError),
    #[error("cannot parse certificate")]
    Parse(#[source] NomErr<X509Error>),
    #[error("cannot read common name")]
    CommonName(#[source] Utf8Error),
    #[error("cannot read friendly name")]
    FriendlyName(#[source] std::io::Error),
    #[error("cannot read description")]
    Description(#[source] std::io::Error),
    #[error("description is not valid utf8")]
    DescriptionUtf8(#[source] Utf8Error),
    #[error("cannot read certificate subject alternative names")]
    San(#[source] X509Error),
    #[error("cannot parse certificate timestamp")]
    Timestamp,
    #[error("cannot parse pfx")]
    Pfx(#[source] std::io::Error),
    #[error("password is not a string")]
    Password(#[source] ShellError),
    #[error("cannot parse der")]
    Der(#[source] NomErr<X509Error>),
    #[error("cannot read fingerprint")]
    Fingerprint(#[source] std::io::Error),
}

impl From<CerError> for LabeledError {
    fn from(value: CerError) -> Self {
        match &value {
            CerError::Pem(source) => {
                LabeledError::new(value.to_string()).with_help(format!("{}", source))
            }
            CerError::Parse(source) => {
                LabeledError::new(value.to_string()).with_help(format!("{}", source))
            }
            CerError::CommonName(source) => {
                LabeledError::new(value.to_string()).with_help(format!("{}", source))
            }
            CerError::FriendlyName(source) => {
                LabeledError::new(value.to_string()).with_help(format!("{}", source))
            }
            CerError::Description(source) => {
                LabeledError::new(value.to_string()).with_help(format!("{}", source))
            }
            CerError::San(source) => {
                LabeledError::new(value.to_string()).with_help(format!("{}", source))
            }
            CerError::Timestamp => LabeledError::new(value.to_string()),
            CerError::Pfx(source) => {
                LabeledError::new(value.to_string()).with_help(format!("{}", source))
            }
            CerError::Password(source) => {
                LabeledError::new(value.to_string()).with_help(format!("{}", source))
            }
            CerError::Der(source) => {
                LabeledError::new(value.to_string()).with_help(format!("{}", source))
            }
            CerError::Fingerprint(source) => {
                LabeledError::new(value.to_string()).with_help(format!("{}", source))
            }
            CerError::DescriptionUtf8(source) => {
                LabeledError::new(value.to_string()).with_help(format!("{}", source))
            }
        }
    }
}
