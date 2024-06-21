use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc;
use std::thread;
use std::io::Result;

use std::time::Duration;

pub(crate) fn connect(delay: u64) -> Result<TcpStream> {
    let reconnect_delay = Duration::from_millis(delay);
    loop {
        match connexion() {
            Ok(x) => return Ok(x),
            Err(_) => { thread::sleep(reconnect_delay); }
        }
    }
}


fn connexion() -> Result<TcpStream> {
    match TcpStream::connect("127.0.0.1:4242"){
        Ok(stream) => {
            println!("Connexion établie avec le serveur");
            Ok(stream)
        }
        Err(e) => {
            eprintln!("Erreur lors de la connexion au serveur: {}", e);
            Err(e)
        }
    }
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
                thread::sleep(Duration::new(3, 0));

            }
            Err(err) => {
                eprintln!("Erreur lors de la lecture: {}", err);
                break;
            }
        }
    }
}

