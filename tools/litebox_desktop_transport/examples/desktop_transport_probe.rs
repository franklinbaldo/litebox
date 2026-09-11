use litebox_desktop_transport::{BoundedQueue, Handshake};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let queue = BoundedQueue::new(2)?;
    queue.push(b"input".to_vec())?;
    assert_eq!(queue.pop()?, Some(b"input".to_vec()));

    let handshake = Handshake::new(1024, 0)?;
    assert_eq!(Handshake::decode(handshake.encode())?, handshake);
    // The probe is intentionally protocol-only; no game or SDL is involved.
    println!(
        "desktop_fd_v1 probe ready; handshake bytes={}",
        handshake.encode().len()
    );
    Ok(())
}
