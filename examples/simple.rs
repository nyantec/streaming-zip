use streaming_zip::Archive;
use streaming_zip::CompressionMode;
use chrono::NaiveDateTime;
use std::io::Cursor;

fn main() -> std::io::Result<()> {
    let stdout = std::io::stdout();
    let handle = stdout.lock();

    let mut archive = Archive::new(handle);
    {
        let name = b"foo".to_vec();
        let mut content = Cursor::new(b"bar".to_vec());
        archive.add_file(name, NaiveDateTime::from_timestamp(1643088493, 0), CompressionMode::Store, &mut content)?;
    }
    drop(archive.finish()?);

    Ok(())
}
