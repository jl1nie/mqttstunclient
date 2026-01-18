use log::{info, trace};
use mqttstunclient::MQTTStunClient;
use std::net::UdpSocket;
use wksocket::{WkListener, challenge};
fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();
    let server_name = "jl1nie/wifikey2".to_string();
    let server_password = "wifikey2-server".to_string();
    let mut server = MQTTStunClient::new(server_name, "wifikey2-server", None, None);

    let udp = UdpSocket::bind("0.0.0.0:0").unwrap();
    if let Some(client_addr) = server.get_client_addr(&udp) {
        println!(
            "\nよっしゃ！クライアントのアドレス {} をゲットだぜ！✨",
            client_addr
        );
    }
    let mut listener = WkListener::bind(udp).unwrap();
    println!("クライアントからのメッセージ、待機中…ワクワク！🤩");
    match listener.accept() {
        Ok((session, addr)) => {
            info!("Accept new session from {}", addr);
            if let Ok(_magic) = challenge(session.clone(), &server_password) {
                info!("Auth. success.");
            } else {
                info!("Auth. failure.");
                session.close().unwrap();
            };
            info!("Auth. Success.");
        }
        Err(e) => {
            trace!("err = {}", e);
        }
    }
    /*
            let mut receive_buffer = [0u8; 1024];
            udp.set_read_timeout(Some(std::time::Duration::from_secs(60)))
                .expect("タイムアウト設定失敗とかありえる？"); // ちょっと長めに60秒待つ

            match udp.recv_from(&mut receive_buffer) {
                Ok((number_of_bytes, source_addr)) => {
                    // source_addr は実際にパケットが来たアドレス！
                    println!(
                        "\nキタ――(ﾟ∀ﾟ)――!! クライアント {} から {} バイト受信！💌 (期待してたのは {} だよん)",
                        source_addr, number_of_bytes, client_addr
                    );
                    let received_message = String::from_utf8_lossy(&receive_buffer[..number_of_bytes]);
                    println!(
                        "受信メッセージ: 「{}」ちゃんと届いたぜ！👍",
                        received_message
                    );

                    // クライアントに愛を込めて返信するのだ！
                    let reply_message = format!(
                        "サーバーだよー！「{}」ってメッセージ、しかと受け取ったぜ！😉 返信フロム {}！",
                        received_message,
                        udp.local_addr().unwrap()
                    );
                    println!(
                        "クライアント {} に「{}」って返信するね！",
                        source_addr, reply_message
                    );

                    match udp.send_to(reply_message.as_bytes(), source_addr) {
                        // 来たアドレスに返信！
                        Ok(bytes_sent) => {
                            println!(
                                "{} バイトの返信、送信完了！ミッションコンプリート！✨",
                                bytes_sent
                            );
                        }
                        Err(e) => {
                            eprintln!("あちゃー、返信の送信失敗…しょぼんぬ…(´・ω・｀): {}", e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "\nうーん、クライアントからのメッセージ受信失敗…タイムアウトかな？(´・ω・｀): {}",
                        e
                    );
                    println!(
                        "クライアントくん、道に迷っちゃったんかな…？それか、まだNATの壁が…（以下略）"
                    );
                }
            }
        } else {
            println!(
                "\nクライアントのアドレスゲットできんかった…誰とも話せないとか、ぼっちサーバーじゃん…orz"
            );
        }
        println!("\nサーバー処理おわり！おつかれー！👋");
    */
}
