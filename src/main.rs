use std::io::prelude::*;
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::collections::HashMap;

use rustls::Session;
use url::Url;

fn handle_connection(mut stream: TcpStream) {
    let mut data = [0 as u8; 1026];
    match stream.read(&mut data) {
        Ok(size) => {
            println!(
                "Data({}): {}",
                size,
                String::from_utf8_lossy(&data[0..size])
            );
            if data[size - 2] == '\r' as u8 && data[size - 1] == '\n' as u8 {
                println!("Valid request");
                stream.write(b"20 text/gemini\r\n# Hello World\nTesting");
            }
        }
        Err(_) => {}
    }
}

fn make_tls_config(cert_path: &str, key_path: &str) -> std::sync::Arc<rustls::ServerConfig> {
    // cert
    let certfile = std::fs::File::open(cert_path).expect("cannot open certificate file");
    let mut certreader = std::io::BufReader::new(certfile);
    let certs = rustls::internal::pemfile::certs(&mut certreader).unwrap();

    // key
    let keyfile = std::fs::File::open(key_path).expect("cannot open key file");
    let mut keyreader = std::io::BufReader::new(keyfile);
    let key = rustls::internal::pemfile::rsa_private_keys(&mut keyreader).unwrap()[0].clone();

    // config
    let mut cfg = rustls::ServerConfig::new(rustls::NoClientAuth::new());
    cfg.set_single_cert(certs, key)
        .expect("cannot set cert");
    cfg.set_protocols(&[b"gemini".to_vec(), b"h2".to_vec(), b"http/1.1".to_vec()]);

    // done
    std::sync::Arc::new(cfg)
}

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:1965")?;
    println!("Gemini Server Started");
    let cfg = make_tls_config("test.pem", "test.key");

    for stream in listener.incoming() {
        println!("Connection established");
        let mut s = stream.unwrap();
        let mut tls_conn = rustls::ServerSession::new(&cfg);
        thread::spawn(move || {
            //handle_connection(stream?);
            println!("Start TLS Handshake");
            while tls_conn.is_handshaking() {
                if tls_conn.wants_read() {
                    match tls_conn.read_tls(&mut s) {
                        Ok(0) => {
                            println!("eof");
                            break;
                        }
                        Err(e) => {
                            println!("Read TLS Error: {}", e);
                        }
                        Ok(_) => {}
                    }
                    match tls_conn.process_new_packets() {
                        Ok(_) => {}
                        Err(e) => {
                            println!("Process Packet Error: {}", e);
                        }
                    }
                }
                while tls_conn.wants_write() {
                    tls_conn.write_tls(&mut s);
                }
            }
            println!("End TLS Handshake");

            if tls_conn.wants_read() {
                match tls_conn.read_tls(&mut s) {
                    Ok(0) => {
                        println!("eof");
                    }
                    Err(e) => {
                        println!("Read TLS Error: {}", e);
                    }
                    Ok(_) => {}
                }
                match tls_conn.process_new_packets() {
                    Ok(_) => {
                        let mut data = [0 as u8; 1026];
                        let size = tls_conn.read(&mut data).unwrap();
                        if data[size - 2] == '\r' as u8 && data[size - 1] == '\n' as u8 {
                            println!("Valid Request");
                            let url =
                                Url::parse(&String::from_utf8_lossy(&data[0..size - 2])).unwrap();
                            tls_conn.write(b"20 text/gemini\r\n");

                            let mut routes = HashMap::new();
                            let mut file =
                                std::fs::File::open("test.gmi").expect("cannot open gmi file");
                            let mut buf = [0 as u8; 1024];
                            loop {
                                let n = file.read(&mut buf).unwrap();
                                if n == 0 {
                                    break;
                                }
                                tls_conn.write(&buf[..n]);
                                while tls_conn.wants_write() {
                                    let size = tls_conn.write_tls(&mut s).unwrap();
                                    println!("Write {}", size);
                                }
                            }

                            println!("Url: {}", url);
                        } else {
                            println!(
                                "Invalid Request: {}",
                                &String::from_utf8_lossy(&data[0..size - 2])
                            );
                        }
                    }
                    Err(e) => {
                        println!("Process Packet Error: {}", e);
                    }
                }
            }

            tls_conn.send_close_notify();

            while tls_conn.wants_write() {
                let size = tls_conn.write_tls(&mut s).unwrap();
                println!("Write {}", size);
            }

            s.shutdown(std::net::Shutdown::Both);
        });
    }

    Ok(())
}
