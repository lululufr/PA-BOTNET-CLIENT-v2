use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc;
use std::time::Duration;

pub(crate) fn connexion() -> std::io::Result<TcpStream> {
    let stream =  TcpStream::connect("51.77.193.65:4242");
    println!("Connexion établie avec le serveur");
    return stream;
}


pub(crate) fn emission(mut stream: TcpStream, channel: mpsc::Receiver<Vec<u8>>){
    loop {
        match channel.recv() {
            Ok(mut message) => {
                // Handle the received message
                stream.write_all(&mut message).expect("Erreur lors de l'envoi du message");
            }
            Err(err) => {
                eprintln!("Error receiving data from channel: {}", err);
                // Handle the error more gracefully, or break out of the loop
                break;
            }
        }
    }
    //if("stop-thread".eq(std::str::from_utf8(&mut message).unwrap())){
    //    break;
    //}
}


pub(crate) fn reception(mut stream: TcpStream, channel: mpsc::Sender<Vec<u8>>) {
    let mut data = Vec::new();
    let mut n_received = 0;
    let mut total_received = 0;
    let mut buffer:[u8; 4096] = [0; 4096];
    let mut end = false;

    stream.set_read_timeout(Some(Duration::new(5, 0)));
    
    println!("[+] receiving data");

    loop {
        match stream.read(&mut buffer){
            Ok(bytes_read) => {
                n_received = bytes_read;

                if bytes_read == 0 {
                    // La connexion a été fermée
                    break;
                }
                total_received += bytes_read;
                println!("[+] received {} bytes", bytes_read);
        
                //ajout des octets au vecteur
                data.extend_from_slice(&buffer[..bytes_read]);
                println!("[+] data added");

            }
            Err(e) => {
                println!("[!] Error while receiving data");
                n_received = 0;
                break;
            }
        }
        if n_received == 0 {
            break;
        }
    }

    println!("[+] received {} bytes", total_received);
    channel.send(buffer[..total_received].to_vec()).unwrap();
}
