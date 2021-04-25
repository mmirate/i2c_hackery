use i2c_hackery::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut keypad = hal::SparkfunKeypad::new("/dev/i2c-1", 0x4B)?;

    let value = keypad.read().await?;

    println!("Read value: {:?}", value);
    Ok(())
}
