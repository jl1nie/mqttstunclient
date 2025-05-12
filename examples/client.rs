use mqttstunclient::MQTTStunClient;
use std::net::UdpSocket;

fn main() {
    println!("クライアント起動！サーバーに愛を届けるぞー！💖");
    let mqtt_topic = "jl1nie/wifikey".to_string(); // トピック名はサーバーと合わせないとね！
    let mut client_logic = MQTTStunClient::new(mqtt_topic, "wifykeypassphrase"); // 変数名変えた！

    // ポート番号は0にしてOSにおまかせ！その方がNAT越えしやすいってウワサも…？
    let udp_socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => {
            println!(
                "UDPソケット、{} でバインド成功！👍",
                s.local_addr().unwrap()
            );
            s
        }
        Err(e) => {
            eprintln!(
                "UDPソケットのバインド失敗とか、マジありえないんだけど…💀: {}",
                e
            );
            return;
        }
    };

    // サーバーのアドレスをMQTT経由でゲット！（この中でホールパンチングもしてるはず！）
    if let Some(server_addr) = client_logic.get_server_addr(&udp_socket) {
        println!(
            "\nやったー！サーバーのアドレス {} をゲットだぜ！✨",
            server_addr
        );

        let message = "クライアントから愛のメッセージ！届けー！💌";
        println!("「{}」ってメッセージをサーバーに送るよ！", message);

        match udp_socket.send_to(message.as_bytes(), server_addr) {
            Ok(bytes_sent) => {
                println!(
                    "{} バイトのメッセージ送信成功！サーバーからの返事、待ってみる？🤔",
                    bytes_sent
                );

                // サーバーからの返信を待つ！ドキドキ…
                let mut receive_buffer = [0u8; 1024];
                udp_socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(30)))
                    .expect("タイムアウト設定失敗とかありえる？"); // 5秒くらい待ってみる

                match udp_socket.recv_from(&mut receive_buffer) {
                    Ok((number_of_bytes, source_addr)) => {
                        println!(
                            "\nキタ――(ﾟ∀ﾟ)――!! サーバー {} から {} バイトの返信きたぁぁぁ！💌",
                            source_addr, number_of_bytes
                        );
                        let received_message =
                            String::from_utf8_lossy(&receive_buffer[..number_of_bytes]);
                        println!(
                            "サーバーからのメッセージ: 「{}」やったね！🎉",
                            received_message
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "\nあちゃー、サーバーからの返信、受信失敗…しょぼんぬ…(´・ω・｀): {}",
                            e
                        );
                        println!("サーバー忙しかったんかな…？それか、まだNATの壁が厚いとか…？🤔");
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "\nうわーん、メッセージ送信失敗…Connection refused とか言われたんだけど？！ぴえん🥺: {}",
                    e
                );
                println!("もしかしてサーバー側がまだ準備できてないとか、ファイアウォールとか…？");
            }
        }
    } else {
        println!("\nサーバーのアドレスゲットできんかった…通信できんとかオワタ…orz");
    }
    println!("\nクライアント処理おわり！またねー！👋");
}
