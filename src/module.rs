use std::process::Command;
use std::str;

pub(crate) fn main(exe: &str, arg: &str)-> String{
    // Commande à exécuter
    let output = Command::new(exe)
        .arg(arg)
        .output()
        .expect("échec à exécuter la commande");

    // Convertir la sortie en string
    let stdout = str::from_utf8(&output.stdout).expect("échec à convertir la sortie en string");

    // Mettre la sortie dans une variable
    let sortie = stdout.to_string();

    sortie

}