#[warn(clippy::all)]

pub mod hal {

    use std::path::Path;

    use embedded_hal::blocking::i2c::{Read, Write, WriteRead};
    use linux_embedded_hal::{i2cdev::linux::LinuxI2CError, I2cdev};

    pub struct I2CDevice {
        dev: I2cdev,
        addr: u8,
    }

    pub type Error = LinuxI2CError;
    pub type Result<T> = std::result::Result<T, Error>;

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
        pub fn write(&mut self, text: &str, line: u8, column: u8, everycolumn: bool) -> Result<()> {
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
                    use std::io::{Cursor, Write};
                    let line = line + (i % 256) as u8;
                    let column = if i == 0 || everycolumn { column } else { 0 };
                    let mut ret = [0u8; 22];
                    let mut writer = Cursor::new(&mut ret[..]);

                    writer.write_all(&[254, lineno(line, column)]).unwrap();
                    writer
                        .write_all(
                            s.as_bytes()
                                .chunks(20 - column as usize)
                                .next()
                                .unwrap_or_default(),
                        )
                        .unwrap();
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
            lines: impl IntoIterator<Item = impl AsRef<str>>,
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
            let lines = lines
                .into_iter()
                .enumerate()
                .flat_map(|(i, s)| {
                    use std::io::Write;
                    let line = line + (i % 256) as u8;
                    let column = if i == 0 || everycolumn { column } else { 0 };
                    let mut ret = [0u8; 22];
                    ret.as_mut();
                    (&mut ret[0..2])
                        .write_all(&[254, lineno(line, column)])
                        .unwrap();
                    (&mut ret[2..])
                        .write_all(s.as_ref().as_bytes().chunks(20).next().unwrap_or_default())
                        .unwrap();
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
    use regex_automata::DFA;
    use thiserror::Error;

    use super::hal::{self, EncoderReading, SerLCD, SparkfunEncoder, SparkfunKeypad};
    use std::borrow::Cow;

    #[derive(Error, Debug)]
    pub enum UiError {
        #[error("i2c bus fault")]
        I2C(#[from] hal::Error),
        #[error("regex syntax problem")]
        Regex(#[from] regex_automata::Error),
    }

    pub type Result<T> = std::result::Result<T, UiError>;

    pub fn menu<'a>(
        options: &'a [Cow<'_, str>],
    ) -> Box<dyn FnMut(&mut SerLCD, &mut SparkfunEncoder, usize) -> Result<Option<usize>> + 'a>
    {
        fn offset(i: i16, len: usize) -> usize {
            let rem = i % len as i16;
            if rem < 0 {
                len + ((-rem) as usize)
            } else {
                rem as usize
            }
        }
        Box::new(move |lcd, encoder, start: usize| {
            encoder.tare(0)?;
            let mut cursor = start;
            use EncoderReading::*;
            while let Position(x) = encoder.read()? {
                let old_cursor = cursor;
                cursor = offset(x, options.len());
                if cursor != old_cursor {
                    lcd.write(">", (cursor % 4) as u8, 0, false)?;
                    if cursor / 4 != old_cursor / 4 {
                        let first_idx = cursor / 4 * 4;
                        let lines = &options[first_idx..first_idx + 4];
                        lcd.write_lines(lines, 0, 2, true)?;
                    }
                }
            }
            Ok(Some(cursor))
        })
    }

    pub fn code_confirmation(message: &'static str) -> Box<dyn FnMut(&mut SerLCD, &mut SparkfunKeypad, u32) -> Result<()> + 'static> {
        Box::new(move |lcd, keypad, expectation| {
            lcd.clear()?;
            lcd.write(message, 0, 0, false)?;
            lcd.write(&format!("code: {}", expectation), 3, 0, false)?;
            //lcd.write("", 3, "code: ".len() as u8, false)?;
            let mut last_refresh = Some(std::time::Instant::now());

            let matcher = match regex_automata::DenseDFA::new(&expectation.to_string())?.to_u16()? {
                regex_automata::DenseDFA::PremultipliedByteClass(d) => Box::new(d),
                _ => unreachable!(),
            };
            let mut state = matcher.start_state();

            while !matcher.is_match_state(state) {
                if last_refresh
                    .map(|i| i.elapsed().as_secs() > 5)
                    .unwrap_or(true)
                {
                    lcd.clear()?;
                    lcd.write(message, 0, 0, false)?;
                    lcd
                        .write(&format!("code: {}", expectation).as_ref(), 3, 0, false)?;
                    last_refresh = Some(std::time::Instant::now())
                }
                match keypad.read()? as u8 {
                    0 => {}
                    c => {
                        // state always comes from the DFA, so elide bounds checks
                        state = unsafe { matcher.next_state_unchecked(state, c) };
                    }
                }
                if matcher.is_dead_state(state) {
                    last_refresh.take();
                    lcd.write("********************", 3, 0, false)?;
                    state = matcher.start_state();
                }
            }
            Ok(())
        })
    }


}
