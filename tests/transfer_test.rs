use beam_rs::core::crypto::{CHUNK_SIZE, encrypt, generate_key};
use beam_rs::core::transfer::{
    ControlSignal, FileHeader, recv_control, recv_encrypted_chunk, recv_encrypted_header,
    run_receiver_transfer, run_sender_transfer, send_control, send_encrypted_chunk,
    send_encrypted_header,
};
use tokio::io::duplex;

#[tokio::test]
async fn test_encrypted_header_roundtrip() {
    let (mut client, mut server) = duplex(4096);
    let key = generate_key();
    let header = FileHeader::new("test_file.txt".to_string(), 12345, 0xABCD);

    let send_handle =
        tokio::spawn(async move { send_encrypted_header(&mut client, &key, &header).await });

    let received = recv_encrypted_header(&mut server, &key).await.unwrap();
    send_handle.await.unwrap().unwrap();

    assert_eq!(received.filename, "test_file.txt");
    assert_eq!(received.file_size, 12345);
    assert_eq!(received.checksum, 0xABCD);
}

#[tokio::test]
async fn test_header_rejects_path_traversal() {
    let header = FileHeader::new("../etc/passwd".to_string(), 1, 0);
    let bytes = header.to_bytes().unwrap();
    assert!(FileHeader::from_bytes(&bytes).is_err());
}

#[tokio::test]
async fn test_encrypted_multi_chunk_roundtrip() {
    let file_size = CHUNK_SIZE * 2 + 1000; // requires 3 chunks
    let (mut client, mut server) = duplex(file_size + 4096);
    let key = generate_key();

    let file_data: Vec<u8> = (0..file_size).map(|i| (i % 256) as u8).collect();

    let file_data_clone = file_data.clone();
    let send_handle = tokio::spawn(async move {
        for chunk in file_data_clone.chunks(CHUNK_SIZE) {
            send_encrypted_chunk(&mut client, &key, chunk).await.unwrap();
        }
    });

    let mut received_data = Vec::new();
    while received_data.len() < file_size {
        received_data.extend(recv_encrypted_chunk(&mut server, &key).await.unwrap());
    }

    assert_eq!(received_data, file_data);
    send_handle.await.unwrap();
}

#[tokio::test]
async fn test_control_signal_roundtrip() {
    let (mut client, mut server) = duplex(4096);
    let key = generate_key();
    let signals = vec![
        ControlSignal::Proceed,
        ControlSignal::Abort,
        ControlSignal::Ack,
        ControlSignal::Resume(u64::MAX - 7),
    ];

    let signals_clone = signals.clone();
    let send_handle = tokio::spawn(async move {
        for signal in &signals_clone {
            send_control(&mut client, &key, signal).await.unwrap();
        }
    });

    for expected in signals {
        assert_eq!(recv_control(&mut server, &key).await.unwrap(), expected);
    }
    send_handle.await.unwrap();
}

#[tokio::test]
async fn test_encrypted_wrong_key_fails_on_header() {
    let (mut client, mut server) = duplex(4096);
    let sender_key = generate_key();
    let receiver_key = generate_key();

    let header = FileHeader::new("secret.txt".to_string(), 1000, 0);

    let send_handle = tokio::spawn(async move {
        send_encrypted_header(&mut client, &sender_key, &header)
            .await
            .unwrap();
    });

    assert!(recv_encrypted_header(&mut server, &receiver_key).await.is_err());
    send_handle.await.unwrap();
}

#[tokio::test]
async fn test_encrypted_wrong_key_fails_on_chunk() {
    let (mut client, mut server) = duplex(4096);
    let sender_key = generate_key();
    let receiver_key = generate_key();

    let send_handle = tokio::spawn(async move {
        send_encrypted_chunk(&mut client, &sender_key, b"Sensitive data")
            .await
            .unwrap();
    });

    assert!(recv_encrypted_chunk(&mut server, &receiver_key).await.is_err());
    send_handle.await.unwrap();
}

#[tokio::test]
async fn test_same_data_encrypts_differently() {
    let data = b"Identical file content for both transfers";
    let key = generate_key();

    let encrypted1 = encrypt(&key, data).unwrap();
    let encrypted2 = encrypt(&key, data).unwrap();

    assert_ne!(&encrypted1[..12], &encrypted2[..12], "nonces must be unique");
    assert_ne!(encrypted1, encrypted2);
}

/// Run a full sender/receiver exchange over an in-memory duplex.
async fn transfer(src: &std::path::Path, out_dir: &std::path::Path, key: [u8; 32]) {
    let (mut sender_stream, mut receiver_stream) = duplex(1024 * 1024);
    let prepared = beam_rs::core::transfer::prepare_file_for_send(src)
        .await
        .unwrap();
    let mut file = prepared.file;
    let header = prepared.header;

    let sender = tokio::spawn(async move {
        run_sender_transfer(&mut file, &mut sender_stream, &key, &header)
            .await
            .unwrap()
    });

    run_receiver_transfer(
        &mut receiver_stream,
        &key,
        Some(out_dir.to_path_buf()),
        false,
    )
    .await
    .unwrap();
    sender.await.unwrap();
}

#[tokio::test]
async fn test_full_transfer_resumes_from_partial_file() {
    use beam_rs::core::resume::{
        ResumeMetadata, calculate_file_checksum, create_resume_file, temp_file_path,
        update_resume_metadata,
    };
    use std::io::Write;

    let src_dir = tempfile::tempdir().unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let src = src_dir.path().join("data.bin");
    let data: Vec<u8> = (0..CHUNK_SIZE * 5 + 123).map(|i| (i * 7 % 251) as u8).collect();
    std::fs::write(&src, &data).unwrap();

    // Simulate an interrupted download holding the first two chunks.
    let received = (CHUNK_SIZE * 2) as u64;
    let final_path = out_dir.path().join("data.bin");
    let mut metadata = ResumeMetadata {
        checksum: calculate_file_checksum(&src).await.unwrap(),
        file_size: data.len() as u64,
        bytes_received: 0,
        filename: "data.bin".to_string(),
    };
    let mut partial = create_resume_file(&temp_file_path(&final_path), &metadata).unwrap();
    partial.write_all(&data[..received as usize]).unwrap();
    metadata.bytes_received = received;
    update_resume_metadata(&mut partial, &metadata).unwrap();
    drop(partial);

    transfer(&src, out_dir.path(), generate_key()).await;

    assert_eq!(std::fs::read(&final_path).unwrap(), data);
    assert!(!temp_file_path(&final_path).exists());
}
