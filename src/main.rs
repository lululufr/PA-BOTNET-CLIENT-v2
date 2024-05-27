mod connexion;

use std::borrow::Borrow;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::thread;
use std::str;

use String;
use std::sync::mpsc;

// Handshake
use rsa::{RsaPublicKey, RsaPrivateKey, Pkcs1v15Encrypt};
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rand::rngs::OsRng;

use serde_json;


use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

use serde::{Deserialize, Serialize};

use generic_array::GenericArray;

use base64::{Engine as _, engine::{ general_purpose}};

//use machine_uid::get;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

// JSON config handshake




fn get_user_input() -> String {
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Erreur lors de la saisis du message");
    input.trim().to_string()
}


#[derive(Serialize, Deserialize)]
struct HandshakeConfJson{
    action: String,
    b64symetric: String,
    b64iv: String,
    multithread: bool,
    stealth: bool
}




fn json_to_struct_handshake_stc(data: String) -> HandshakeConfJson {
    let p = serde_json::from_str::<HandshakeConfJson>(&data).expect("Erreur JSON");
    p
}

fn struct_to_json_handshake_stc(data:HandshakeConfJson) -> String{
    let json_string = serde_json::to_string(&data);
    json_string.unwrap()
}

fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}


fn send_encrypted_data_to_server(sender:mpsc::Sender<Vec<u8>>,
                                 data:String,
                                 symetric_key:GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
                                 iv:GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>){

    let data_as_bytes = data.as_bytes().to_vec();
    let mut bufff = [0u8; 94];
    let encrypted_data = Aes128CbcEnc::new(&symetric_key, &iv)
        .encrypt_padded_b2b_mut::<Pkcs7>(&data_as_bytes, &mut bufff)
        .unwrap();

    match sender.send(encrypted_data.to_vec()) {
        Ok(()) => {
            println!("Data sent successfully!");
        }
        Err(err) => {
            eprintln!("Error sending data: {}", err);
            // Handle the error more gracefully
        }
    }
}



fn receive_encrypted_data_from_server(receiver:&mpsc::Receiver<Vec<u8>>,
                                      symetric_key:GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
                                      iv:GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>)
                                      -> String{
    match receiver.recv() {
        Ok(data) => {
            println!("Data received successfully!");

            println!("Data received : {:?}", data);

            let mut bufff = [0u8; 94];
            let decrypted_data = Aes128CbcDec::new(&symetric_key, &iv)
                .decrypt_padded_b2b_mut::<Pkcs7>(&data, &mut bufff)
                .unwrap_or_default();

            match str::from_utf8(&decrypted_data) {
                Ok(utf8_data) => utf8_data.to_string(),
                Err(err) => {
                    eprintln!("Error converting data to UTF-8: {:?}", err);
                    // Handle the error more gracefully, return a default string for now
                    String::new()
                }
            }
        }
        Err(err) => {
            eprintln!("Error while receiving data: {:?}", err);
            // Handle the error more gracefully, return a default string for now
            String::new()
        }
    }

}


fn main() -> io::Result<()> {

    // Connexion
    let connexion:TcpStream = connexion::connexion()?;
    let connexion2:TcpStream = connexion.try_clone()?;

    // thread emission
    let (sender, rx) = mpsc::channel::<Vec<u8>>();
    let _thread_emission = thread::spawn(move|| {
        connexion::emission(connexion, rx);
    });

    // thread reception
    let (tx2, receiver) = mpsc::channel::<Vec<u8>>();
    let _thread_reception = thread::spawn(move|| {
        connexion::reception(connexion2, tx2);
    });


    // ========== HANDSHAKE ==========

    // Génération de la paire de clés RSA
    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    let pkcs1_encoded_public_pem = public_key.to_public_key_pem(LineEnding::LF).unwrap();


    // Envois de la clé publique au serveur python
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
    match general_purpose::STANDARD.decode(handshake_data.b64symetric.as_bytes()){
        Ok(decoded_sym_key) => {
            // Successfully decoded, assign the value to iv
            symetric_key = GenericArray::clone_from_slice(&decoded_sym_key);
        }
        Err(err) => {
            eprintln!("Error decoding base64 symetric key: {}", err);
            // Handle the error, for now, let's assign an empty Vec<u8>
            symetric_key = GenericArray::default();
        }
    };

    // Decode the base64 iv
    let iv;
    match general_purpose::STANDARD.decode(handshake_data.b64iv.as_bytes()){
        Ok(decoded_iv) => {
            // Successfully decoded, assign the value to iv
            iv = GenericArray::clone_from_slice(&decoded_iv);
        }
        Err(err) => {
            eprintln!("Error decoding base64 iv: {}", err);
            // Handle the error, for now, let's assign an empty Vec<u8>
            iv = GenericArray::default();
        }
    };


    let uid = machine_uid::get().unwrap();

    let handshake_response:String = format!("{{\"action\":\"client_config\",\"uid\":\"{}\"}}", uid);

    send_encrypted_data_to_server(sender.clone(), handshake_response, symetric_key, iv);

    // ========== END HANDSHAKE ==========


    let _thread_test = thread::spawn(move|| {
        loop {
            println!("Message Recu : {}", receive_encrypted_data_from_server(receiver.borrow(), symetric_key, iv));
        }
    });

    loop {
        // Réception des ordres du serveur
        let mut input = String::new();
        println!("Entrez un message : ");

        match io::stdin().read_line(&mut input) {
            Ok(_n) => {
                println!("{}", input);

                send_encrypted_data_to_server(sender.clone(), input, symetric_key, iv);
            }
            Err(error) => println!("error: {error}"),
        }
    }

}