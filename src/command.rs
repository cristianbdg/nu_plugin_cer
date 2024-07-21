use chrono::Local;
use nu_plugin::{EngineInterface, EvaluatedCall, PluginCommand, SimplePluginCommand};
use nu_protocol::{record, Category, Example, LabeledError, Signature, SyntaxShape, Value};

use crate::{
    certificate::{get_pem_values, get_pfx_values},
    plugin::CerPlugin,
};

pub struct Cer;

impl SimplePluginCommand for Cer {
    type Plugin = CerPlugin;

    fn name(&self) -> &str {
        "cer"
    }

    fn usage(&self) -> &str {
        "Shows details of a cer/pfx"
    }

    fn examples(&self) -> Vec<nu_protocol::Example> {
        vec![Example {
            example: "open path/to/certificate.cer | cer",
            description: "shows the details of the first certificate in the certificate.cer file",
            result: Some(Value::test_record(record!(
                    "cn" => Value::test_string("cer.com"),
                    "subject" => Value::test_string("CN=cer.com, Email=cer@example.com, O=Example"),
                    "san" => Value::test_string("alternative.com"),
                    "ca" => Value::test_string("ca.com"),
                    "ca_subject" => Value::test_string("CN=ca.com, Email=ca@example.com, O=Example"),
                    "expiration" => Value::test_date(Local::now().into()),
                    "thumbprint" => Value::test_string("8910651b144734559872b321419ff87233fd4392")))),
        }]
    }

    fn signature(&self) -> Signature {
        Signature::build(PluginCommand::name(self))
            .switch(
                "list",
                "return all certificates as a list instead of only the first",
                Some('a'),
            )
            .named(
                "password",
                SyntaxShape::String,
                "password to read the certificate",
                Some('p'),
            )
            .category(Category::System)
    }

    fn search_terms(&self) -> Vec<&str> {
        vec!["certificate", "cer", "pfx"]
    }

    fn run(
        &self,
        _plugin: &CerPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        input: &Value,
    ) -> Result<Value, LabeledError> {
        let span = input.span();
        if let Value::String { val, .. } = input {
            let values = get_pem_values(val, span)?;
            if call.has_flag("list")? {
                let list = Value::list(values, span);
                Ok(list)
            } else {
                values
                    .first()
                    .cloned()
                    .ok_or(LabeledError::new("no certificates in file"))
            }
        } else if let Value::Binary { val, .. } = input {
            let password = call.get_flag_value("password");
            let values = get_pfx_values(val, password, span)?;
            if call.has_flag("list")? {
                let list = Value::list(values, span);
                Ok(list)
            } else {
                values
                    .first()
                    .cloned()
                    .ok_or(LabeledError::new("no certificates in file"))
            }
        } else {
            Err(
                LabeledError::new("Expected certificate input from pipeline").with_label(
                    format!("requires certificate input; got {}", input.get_type()),
                    call.head,
                ),
            )
        }
    }
}
