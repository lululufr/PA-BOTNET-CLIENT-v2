use serde_json;
use serde;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(crate) struct HandshakeConfJson{
    action: String,
    pub(crate) b64symetric: String,
    pub(crate) b64iv: String,
    pub(crate) multithread: bool,
    pub(crate) stealth: bool
}


pub(crate) fn json_to_struct_handshake_stc(data: String) -> HandshakeConfJson {
    let p = serde_json::from_str::<HandshakeConfJson>(&data).expect("Erreur JSON");
    p
}

pub(crate) fn struct_to_json_handshake_stc(data:HandshakeConfJson) -> String{
    let json_string = serde_json::to_string(&data);
    json_string.unwrap()
}