pub mod hal {

    use std::path::Path;

    use embedded_hal::blocking::i2c::{Read, Write, WriteRead};
    use linux_embedded_hal::{i2cdev::linux::LinuxI2CError, I2cdev};

    pub struct I2CDevice {
        dev: I2cdev,
        addr: u8,
    }

    pub type Result<T> = std::result::Result<T, LinuxI2CError>;

    impl I2CDevice {
        pub fn new(path: impl AsRef<Path>, addr: u8) -> Result<Self> {
            Ok(I2CDevice {
                dev: I2cdev::new(path)?,
                addr,
            })
        }
        pub fn read(&mut self, reg: u8) -> Result<u8> {
            let mut buffer = [0; 1];
            self.dev.write_read(self.addr, &[reg], &mut buffer)?;
            Ok(buffer[0])
        }
        pub fn write(&mut self, reg: u8, content: u8) -> Result<()> {
            Ok(self.dev.write(self.addr, &[reg, content])?)
        }
        pub(crate) fn smbus_sendbyte(&mut self, reg: u8) -> Result<()> {
            Ok(self.dev.write(self.addr, &[reg])?)
        }
        pub(crate) fn smbus_recvbyte(&mut self) -> Result<u8> {
            let mut buffer = [0; 1];
            self.dev.read(self.addr, &mut buffer)?;
            Ok(buffer[0])
        }
        pub fn block_read<const COUNT: usize>(&mut self, reg: u8) -> Result<[u8; COUNT]> {
            let mut buffer = [0; COUNT];
            self.dev.write_read(self.addr, &[reg], &mut buffer)?;
            Ok(buffer)
        }
        pub fn block_read_into(&mut self, reg: u8, buffer: &mut [u8]) -> Result<()> {
            Ok(self.dev.write_read(self.addr, &[reg], buffer)?)
        }
        pub fn block_write(&mut self, reg: u8, content: &[u8]) -> Result<()> {
            let mut bytes = vec![reg];
            bytes.extend(content);
            Ok(self.dev.write(self.addr, &bytes)?)
        }
        pub(crate) fn block_write_noreg(&mut self, content: &[u8]) -> Result<()> {
            Ok(self.dev.write(self.addr, &content)?)
        }
    }

    pub struct SerLCD(I2CDevice);
    impl SerLCD {
        pub fn new(path: impl AsRef<Path>, addr: u8) -> Result<Self> {
            Ok(Self(I2CDevice {
                dev: I2cdev::new(path)?,
                addr,
            }))
        }
        pub fn write(
            &mut self,
            text: &str,
            line: u8,
            column: u8,
            everycolumn: bool,
        ) -> Result<()> {

            #[inline]
            fn lineno(line: u8, column: u8) -> u8 {
                let column = column.clamp(0, 19);
                128 + column + 0x20 * (line & 0b10) + 0x64 * (line & 0b01)
            }
            let line = line;
            let column = column.clamp(0, 19);
            let lines = text
                .lines()
                .enumerate()
                .flat_map(|(i, s)| {
                    use std::io::{Cursor,Write};
                    let line = line + (i % 256) as u8;
                    let column = if i == 0 || everycolumn { column } else { 0 };
                    let mut ret = [0u8; 22];
                    let mut writer = Cursor::new(&mut ret[..]);

                    writer.write_all(&[254, lineno(line, column)]).unwrap();
                    writer.write_all(s.as_bytes().chunks(20).next().unwrap_or_default()).unwrap();
                    std::array::IntoIter::new(ret)
                })
                .collect::<Vec<_>>();
            lines
                .chunks(32)
                .try_for_each(|chunk| self.0.block_write_noreg(chunk))?;
            Ok(())
        }
        pub fn write_lines(
            &mut self,
            lines: impl IntoIterator<Item=impl AsRef<str>>,
            line: u8,
            column: u8,
            everycolumn: bool,
        ) -> Result<()> {

            #[inline]
            fn lineno(line: u8, column: u8) -> u8 {
                let column = column.clamp(0, 19);
                128 + column + 0x20 * (line & 0b10) + 0x64 * (line & 0b01)
            }
            let line = line;
            let column = column.clamp(0, 19);
            let lines = lines.into_iter()
                .enumerate()
                .flat_map(|(i, s)| {
                    use std::io::Write;
                    let line = line + (i % 256) as u8;
                    let column = if i == 0 || everycolumn { column } else { 0 };
                    let mut ret = [0u8; 22];
                    ret.as_mut();
                    (&mut ret[0..2]).write_all(&[254, lineno(line, column)]).unwrap();
                    (&mut ret[2..]).write_all(s.as_ref().as_bytes().chunks(20).next().unwrap_or_default()).unwrap();
                    std::array::IntoIter::new(ret)
                })
                .collect::<Vec<_>>();
            lines
                .chunks(32)
                .try_for_each(|chunk| self.0.block_write_noreg(chunk))?;
            Ok(())
        }
        pub fn clear(&mut self) -> Result<()> {
            self.0.block_write_noreg("|-".as_bytes())
        }
        pub fn set_brightness(&mut self, r: u8, g: u8, b: u8) -> Result<()> {
            #[inline]
            fn rerange(x: u8) -> u8 {
                ((((x as u16) << 2) / 35) as u8).clamp(0, 29)
            }
            let buf = [
                '|' as u8,
                rerange(r) + 128,
                '|' as u8,
                rerange(g) + 128 + 30,
                '|' as u8,
                rerange(b) + 128 + 30 + 30,
            ];
            self.0.block_write_noreg(&buf)
        }
    }

    pub struct SparkfunKeypad(I2CDevice);
    impl SparkfunKeypad {
        pub fn new(path: impl AsRef<Path>, addr: u8) -> Result<Self> {
            Ok(Self(I2CDevice {
                dev: I2cdev::new(path)?,
                addr,
            }))
        }
        pub fn read(&mut self) -> Result<char> {
            self.0.write(6, 1)?;
            Ok(self.0.read(3)? as char)
        }
        pub fn slurp(&mut self) -> impl IntoIterator<Item = Result<char>> + '_ {
            std::iter::repeat_with(move || self.read()).take_while(|c| !matches!(c, Ok('\0')))
        }
    }

    pub struct Cap1203(I2CDevice);
    impl Cap1203 {
        pub fn new(path: impl AsRef<Path>, addr: u8) -> Result<Self> {
            let mut this = Self(I2CDevice {
                dev: I2cdev::new(path)?,
                addr,
            });
            this.0.smbus_sendbyte(3)?;
            Ok(this)
        }
        pub fn read(&mut self) -> Result<u8> {
            Ok(self.0.smbus_recvbyte()? & 0b111)
        }
    }

    pub enum EncoderReading {
        Position(i16),
        ButtonClick,
    }
    impl From<Option<i16>> for EncoderReading {
        fn from(o: Option<i16>) -> Self {
            match o {
                Some(x) => Self::Position(x),
                None => Self::ButtonClick,
            }
        }
    }

    pub struct SparkfunEncoder(I2CDevice);
    impl SparkfunEncoder {
        pub fn new(path: impl AsRef<Path>, addr: u8) -> Result<Self> {
            let mut this = Self(I2CDevice {
                dev: I2cdev::new(path)?,
                addr,
            });
            this.0.block_write(5, &[0; 8])?;
            this.clear_flags()?;
            Ok(this)
        }
        pub fn color(&mut self, r: u8, g: u8, b: u8) -> Result<()> {
            self.0.block_write(0x0d, &[r, g, b])
        }
        fn clear_flags(&mut self) -> Result<()> {
            self.0.write(1, 0)
        }
        pub fn tare(&mut self, pos: i16) -> Result<()> {
            self.0
                .block_write(5, &[(pos & 0xff) as u8, (pos >> 8) as u8])
        }
        pub fn read(&mut self) -> Result<EncoderReading> {
            let status = self.0.read(1)? & 0b101;
            let press = status & 0b100 != 0;
            let knob = status & 0b001 != 0;

            let regs = if knob || !press {
                self.0.block_read(5)?
            } else {
                [0u8; 2]
            };
            let knobpos = (regs[0] as u16 | ((regs[1] as u16) << 8)) as i16;

            if status != 0 {
                self.clear_flags()?;
            }
            Ok(Some(knobpos).filter(|_| knob || !press).into())
        }
    }
}

pub mod ui {
    use super::hal::*;
    use std::borrow::Cow;

    pub struct Menu<'a> { lcd: SerLCD, encoder: SparkfunEncoder, options: &'a [Cow<'a, str>], cursor: usize }
    impl<'a> Menu<'a> {
        pub fn new(lcd: SerLCD, mut encoder: SparkfunEncoder, options: &'a [Cow<'_, str>], start: usize) -> Result<Self> {
            encoder.tare(0)?;
            let cursor = start;
            Ok(Self { lcd, encoder, options, cursor })
        }
        pub fn into_inner(self) -> (SerLCD, SparkfunEncoder) { (self.lcd, self.encoder) }
        pub fn tick(&mut self) -> Result<Option<usize>> {
            fn offset(i: i16, len: usize) -> usize {
                let rem = i%len as i16;
                if rem < 0 {
                    len + ((-rem) as usize)
                } else {
                    rem as usize
                }
            }
            use EncoderReading::*;
            Ok(match self.encoder.read()? {
                Position(x) => {
                    let old_cursor = self.cursor;
                    self.cursor = offset(x, self.options.len());
                    if self.cursor != old_cursor {
                        self.lcd.write(">", (self.cursor%4) as u8, 0, false)?;
                        if self.cursor / 4 != old_cursor / 4 {
                            let first_idx = self.cursor / 4 * 4;
                            let lines = &self.options[first_idx..first_idx+4];
                            self.lcd.write_lines(lines, 0, 2, true)?;
                        }
                    }
                    None
                }
                ButtonClick => Some(self.cursor),
            })
        }
    }

    const BUFFERSIZE: usize = 10; // = floor(log10(2^32))
    pub struct CodeConfirmation { lcd: SerLCD, keypad: SparkfunKeypad, message: &'static str, expectation: [u8; BUFFERSIZE], progress: usize, last_refresh: std::time::Instant }
    impl CodeConfirmation {
        pub fn new(mut lcd: SerLCD, keypad: SparkfunKeypad, message: &'static str, expectation: u32) -> Result<Self> {
            lcd.clear()?;
            lcd.write(message, 0, 0, false)?;
            lcd.write(&format!("code: {}", expectation), 3, 0, false)?;
            //lcd.write("", 3, "code: ".len() as u8, false)?;
            let expectation: [u8; BUFFERSIZE] = {
                use std::io::Write;
                let mut ret: [u8; BUFFERSIZE] = Default::default();
                write!(&mut ret[..], "{}", expectation).unwrap();
                ret
            };
            Ok(Self { lcd, keypad, message, expectation, progress: 0, last_refresh: std::time::Instant::now() })
        }
        pub fn into_inner(self) -> (SerLCD, SparkfunKeypad) { (self.lcd, self.keypad) }
        pub fn tick(&mut self) -> Result<bool> {
            if self.last_refresh.elapsed().as_secs() > 5 {
                self.lcd.clear()?;
                self.lcd.write(self.message, 0, 0, false)?;
                self.lcd.write(&format!("code: {}", String::from_utf8_lossy(&self.expectation).as_ref()), 3, 0, false)?;
            }
            Ok(match self.keypad.read()? {
                '\0' if self.expectation.get(self.progress).copied().unwrap_or_default() == 0 => {
                    true
                },
                '\0' => false,
                c if c == self.expectation[self.progress] as char => { self.progress += 1; false }
                _ => { self.progress = 0; false }
            })
        }
    }
}
