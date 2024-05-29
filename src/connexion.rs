use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc;

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
    let mut buffer = [0; 512];

    loop {
        match stream.read(&mut buffer) {
            Ok(bytes_read) => {
                if bytes_read == 0 {
                    // La connexion a été fermée
                    break;
                }

                //let response = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();

                //println!("Received : {}", response);
                //ordre_du_srv(response);
                channel.send(buffer[..bytes_read].to_vec()).unwrap();

            }
            Err(err) => {
                eprintln!("Erreur lors de la lecture: {}", err);
                break;
            }
        }
    }
}
