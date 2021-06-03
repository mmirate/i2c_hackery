#![warn(clippy::all)]
#![warn(clippy::todo)]
#![warn(clippy::pedantic)]
#![warn(clippy::restriction)]
#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::implicit_return)]
#![allow(clippy::blanket_clippy_restriction_lints)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_inline_in_public_items)]
#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]
#![deny(clippy::unwrap_used)]

/*
pub(crate) mod actor_ref {

    struct MyActor {
        receiver: tokio::sync::mpsc::Receiver<ActorMessage>,
        next_id: u32,
    }
    enum ActorMessage {
        GetUniqueId {
            respond_to: tokio::sync::oneshot::Sender<u32>,
        },
    }

    impl MyActor {
        fn new(receiver: tokio::sync::mpsc::Receiver<ActorMessage>) -> Self {
            MyActor {
                receiver,
                next_id: 0,
            }
        }
        fn handle_message(&mut self, msg: ActorMessage) {
            match msg {
                ActorMessage::GetUniqueId { respond_to } => {
                    self.next_id += 1;

                    // The `let _ =` ignores any errors when sending.
                    //
                    // This can happen if the `select!` macro is used
                    // to cancel waiting for the response.
                    let _ = respond_to.send(self.next_id);
                },
            }
        }
    }

    async fn run_my_actor(mut actor: MyActor) {
        while let Some(msg) = actor.receiver.recv().await {
            actor.handle_message(msg);
        }
    }


    #[derive(Clone)]
    pub struct MyActorHandle {
        sender: tokio::sync::mpsc::Sender<ActorMessage>,
    }

    impl MyActorHandle {
        pub fn new() -> Self {
            let (sender, receiver) = tokio::sync::mpsc::channel(8);
            let actor = MyActor::new(receiver);
            tokio::spawn(run_my_actor(actor));

            Self { sender }
        }

        pub async fn get_unique_id(&self) -> u32 {
            let (send, recv) = tokio::sync::oneshot::channel();
            let msg = ActorMessage::GetUniqueId {
                respond_to: send,
            };

            // Ignore send errors. If this send fails, so does the
            // recv.await below. There's no reason to check the
            // failure twice.
            let _ = self.sender.send(msg).await;
            recv.await.expect("Actor task has been killed")
        }
    }
}
 */

pub mod hal {

    mod blocking {

        use embedded_hal::blocking::i2c::{Read, Write, WriteRead};
        use linux_embedded_hal::{i2cdev::linux::LinuxI2CError, I2cdev};
        use std::path::Path;

        struct I2CDeviceImpl {
            dev: I2cdev,
            addr: u8,
        }

        pub type Error = LinuxI2CError;
        pub type Result<T> = std::result::Result<T, Error>;

        pub const I2C_BUFFER_SIZE: usize = 31;

        impl I2CDeviceImpl {
            fn new(path: impl AsRef<Path>, addr: u8) -> Result<Self> {
                Ok(I2CDeviceImpl { dev: I2cdev::new(path)?, addr })
            }
            fn read(&mut self, reg: u8) -> Result<u8> {
                let mut buffer = [0; 1];
                self.dev.write_read(self.addr, &[reg], &mut buffer)?;
                Ok(buffer[0])
            }
            fn write(&mut self, reg: u8, content: u8) -> Result<()> {
                self.dev.write(self.addr, &[reg, content])
            }
            fn smbus_sendbyte(&mut self, reg: u8) -> Result<()> {
                self.dev.write(self.addr, &[reg])
            }
            fn smbus_recvbyte(&mut self) -> Result<u8> {
                let mut buffer = [0; 1];
                self.dev.read(self.addr, &mut buffer)?;
                Ok(buffer[0])
            }
            /*fn block_read_const<const COUNT: usize>(&mut self, reg: u8) -> Result<[u8; COUNT]> {
                let mut buffer = [0; COUNT];
                self.block_read_into(reg, &mut buffer)?;
                Ok(buffer)
            }*/
            fn block_read_u16(&mut self, reg: u8) -> Result<u16> {
                let mut buffer = [0; 2];
                self.block_read_into(reg, &mut buffer)?;
                Ok(u16::from_le_bytes(buffer))
            }
            fn block_read_into(&mut self, reg: u8, buffer: &mut [u8]) -> Result<()> {
                self.dev.write_read(self.addr, &[reg], buffer)
            }
            #[allow(clippy::similar_names)]
            fn block_write_u16(&mut self, reg: u8, content: u16) -> Result<()> {
                let [lsb, msb] = content.to_le_bytes();
                self.dev.write(self.addr, &[reg, lsb, msb])
            }
            fn block_write_u32(&mut self, reg: u8, content: u32) -> Result<()> {
                let [b0, b1, b2, b3] = content.to_le_bytes();
                self.dev.write(self.addr, &[reg, b0, b1, b2, b3])
            }
            fn block_write_u64(&mut self, reg: u8, content: u64) -> Result<()> {
                let [b0, b1, b2, b3, b4, b5, b6, b7] = content.to_le_bytes();
                self.dev.write(self.addr, &[reg, b0, b1, b2, b3, b4, b5, b6, b7])
            }
            /*fn block_write_const<const COUNT: usize>(&mut self, reg: u8, content: [u8; COUNT]) -> Result<()> {
                if COUNT < 32 {
                    let mut bytes = vec![reg];
                    bytes.extend(&content);
                    self.dev.write(self.addr, &*bytes)
                } else {
                    content
                        .chunks(31)
                        .try_for_each(|chunk| {
                            let mut bytes = vec![reg];
                            bytes.extend(chunk);
                            self.dev.write(self.addr, &*bytes)
                        })
                }
            }
            fn block_write_noreg(&mut self, content: &[u8]) -> Result<()> {
                if content.is_empty() { return Ok(()) }
                content
                    .chunks(32)
                    .try_for_each(|bytes| self.dev.write(self.addr, bytes))
            }*/
            fn block_write_noreg_const_ld(&mut self, content: [u8; I2C_BUFFER_SIZE], len: u8) -> Result<()> {
                let bytes = if let Some(x) = content.get(..len.into()) { x } else if let Some(x) = content.get(..) { x } else { return Ok(()); };
                self.dev.write(self.addr, &bytes)
            }
        }

        macro_rules! actions {
            ($actor_name:ident, $message_name:ident, $handle_name:ident, $self:ident {
                $(
                    $variant:ident $method:ident($($param:ident : $type:ty),* $(,)?) -> $returntype:ty $body:block
                ),+ $(,)?
            } ) => {
                #[derive(Debug)]
                pub enum $message_name {
                    $(
                        $variant {
                            $( $param: $type, )*
                            respond_to: tokio::sync::oneshot::Sender<$returntype>,
                        },
                    )+
                }
                impl $actor_name {
                    fn handle_message(&mut $self, msg: $message_name) {
                        match msg {
                            $(
                                $message_name::$variant { $( $param, )* respond_to } => {
                                    let ret: $returntype = $body;
                                    // Ignore any errors when sending.
                                    //
                                    // This can happen if the `select!` macro is used
                                    // to cancel waiting for the response.
                                    drop(respond_to.send(ret));
                                },
                            )+
                        }
                    }
                    fn handle_messages(&mut self) {
                        while let Some(msg) = self.receiver.blocking_recv() {
                            self.handle_message(msg)
                        }
                    }
                }
                impl $handle_name {
                    $(
                        pub async fn $method(&mut self, $($param: $type,)*) -> $returntype {
                            let (send, recv) = tokio::sync::oneshot::channel();
                            let msg = $message_name::$variant { $($param,)* respond_to: send };
                            // Ignore send errors. If this send fails, so does the
                            // recv.await below. There's no reason to check the
                            // failure twice.
                            drop(self.sender.send(msg).await);
                            recv.await.expect("Actor task has been killed")
                        }
                    )+
                }
            }
        }

        struct I2CActorImpl {
            receiver: tokio::sync::mpsc::Receiver<I2CActorMessage>,
            dev: I2CDeviceImpl,
        }
        actions! { I2CActorImpl, I2CActorMessage, I2CActor, self {
            DerefPointer deref_pointer() -> Result<u8> { self.dev.smbus_recvbyte() },
            SetPointer set_pointer(reg: u8) -> Result<()> { self.dev.smbus_sendbyte(reg) },
            Read read(reg: u8) -> Result<u8> { self.dev.read(reg) },
            Write write(reg: u8, content: u8) -> Result<()> { self.dev.write(reg, content) },
            BlockWriteU16 block_write_u16(reg: u8, content: u16) -> Result<()> { self.dev.block_write_u16(reg, content) },
            BlockWriteU32 block_write_u32(reg: u8, content: u32) -> Result<()> { self.dev.block_write_u32(reg, content) },
            BlockWriteU64 block_write_u64(reg: u8, content: u64) -> Result<()> { self.dev.block_write_u64(reg, content) },
            /* BlockWriteNoReg block_write_noreg(content: Box<[u8]>) -> Result<()> { self.dev.block_write_noreg(&*content) }, */
            BlockWriteNoReg32LD block_write_noreg_arr32_ld(content: [u8; I2C_BUFFER_SIZE], len: u8) -> Result<()> { self.dev.block_write_noreg_const_ld(content, len) },
            BlockReadU16 block_read_u16(reg: u8) -> Result<u16> { self.dev.block_read_u16(reg) },
            /* BlockRead block_read(reg: u8, count: u8) -> Result<Box<[u8]>> {
                let mut buffer = vec![0u8; count as usize];
                let r = self.dev.block_read_into(reg, &mut buffer);
                r.map(move |()| buffer.into_boxed_slice())
            }, */
            /* BlockReadInto block_read_into(reg: u8, buffer: Box<[u8]>) -> Result<Box<[u8]>> {
                let mut buffer = buffer;
                let r = self.dev.block_read_into(reg, &mut buffer);
                r.map(move |()| buffer)
            }, */
        } }

        pub struct I2CActor {
            sender: tokio::sync::mpsc::Sender<I2CActorMessage>,
        }
        impl I2CActor {
            pub fn new(path: impl AsRef<Path>, addr: u8) -> Result<Self> {
                let dev = I2CDeviceImpl::new(path, addr)?;
                let (sender, receiver) = tokio::sync::mpsc::channel(1);
                tokio::task::spawn_blocking(|| I2CActorImpl { receiver, dev }.handle_messages());

                Ok(Self { sender })
            }
        }
    }
    use std::{convert::{TryFrom, TryInto}, path::Path};
    use crate::hal::blocking::I2C_BUFFER_SIZE;


    pub use blocking::{Error, I2CActor, Result};

    #[allow(clippy::exhaustive_enums)]
    pub enum LcdBrightness {
        R(u8),
        G(u8),
        B(u8),
    }
    impl From<LcdBrightness> for u8 {
        fn from(this: LcdBrightness) -> Self {
            #![allow(clippy::integer_arithmetic)]
            const BEGIN: u8 = 128;
            const LEN: u8 = 30;
            #[allow(clippy::integer_division)]
            #[inline]
            fn rerange(x: u8) -> u8 {
                u8::try_from(((u16::from(x)) << 2_i32) / 35).expect("u8*2/35 didn't fit into u8").clamp(0, LEN - 1)
            }
            match this {
                LcdBrightness::R(r) => rerange(r) + BEGIN,
                LcdBrightness::G(g) => rerange(g) + BEGIN + LEN,
                LcdBrightness::B(b) => rerange(b) + BEGIN + LEN + LEN,
            }
        }
    }

    const I2C_CHIP_PATH: &'static str = "/dev/i2c-1";

    pub struct SerLcd(I2CActor);
    impl SerLcd {
        const DEFAULT_ADDR: u8 = 0x72;
        pub fn default() -> Result<Self> {
            Self::new(I2C_CHIP_PATH, Self::DEFAULT_ADDR)
        }
        pub fn new(path: impl AsRef<Path>, addr: u8) -> Result<Self> {
            Ok(Self(I2CActor::new(path, addr)?))
        }
        #[inline]
        #[allow(clippy::integer_arithmetic)]
        #[allow(clippy::shadow_reuse)]
        fn lineno(line: u8, column: u8) -> u8 {
            let column = column.clamp(0, 19);
            128 + column + 0x20 * (line & 0b10) + 0x64 * (line & 0b01)
        }
        #[inline]
        pub async fn write(&mut self, text: &str, line: u8, column: u8, everycolumn: bool) -> Result<()> {
            self.write_lines(text.lines(), line, column, everycolumn).await
        }
        #[allow(clippy::integer_arithmetic)]
        pub async fn write_lines(&mut self, lines: impl IntoIterator<Item = impl AsRef<str>>, line: u8, column: u8, everycolumn: bool) -> Result<()> {
            let line = line;
            let column = column.clamp(0, 19);
            for (ret, len) in lines.into_iter().enumerate().map(|(i, s)| {
                let line = line + u8::try_from(i % 256).expect("usize%256 didn't fit into u8");
                let column = if i == 0 || everycolumn { column } else { 0 };
                Self::format_line(s.as_ref(), line, column)
            }) {
                self.0.block_write_noreg_arr32_ld(ret, len).await?;
            }
            Ok(())
        }
        #[inline]
        #[allow(clippy::integer_arithmetic)]
        fn format_line(text: &str, line: u8, column: u8) -> ([u8; I2C_BUFFER_SIZE], u8) {
            use std::io::Write;
            let mut ret = [0_u8; I2C_BUFFER_SIZE];
            ret[0] = 254;
            ret[1] = Self::lineno(line, column);

            let s = text.as_bytes();
            let written_len = (&mut ret[2..22]).write(s).expect("rustig: cosmic ray");
            let len = written_len + 2;

            (ret, len.try_into().expect("20 didn't fit into u8"))
        }
        pub async fn clear(&mut self) -> Result<()> {
            self.0.write(b'|', b'-').await
        }
        pub async fn set_brightness(&mut self, brightness: LcdBrightness) -> Result<()> {
            self.0.write(b'|', brightness.into()).await
        }
    }

    #[allow(clippy::exhaustive_enums)]
    pub enum KeypadReadout<const ASCII: bool> {
        Digit(u8),
        Hash,
        Star
    }
    impl<const ASCII: bool> KeypadReadout<{ ASCII }> {
        #[allow(clippy::integer_arithmetic)]
        fn new(c: u8) -> Option<KeypadReadout<ASCII>> {
            Some(match c {
                x @ (b'0'..=b'9') => { Self::Digit(if ASCII { x } else { x-b'0' }) }
                b'#' => Self::Hash,
                b'*' => Self::Star,
                0 => None?,
                _x => { /* warn: bad keypad output */ None? }
            })
        }
    }

    pub struct SparkfunKeypad(I2CActor);
    impl SparkfunKeypad {
        const DEFAULT_ADDR: u8 = 0x4b;
        pub fn default() -> Result<Self> {
            Self::new(I2C_CHIP_PATH, Self::DEFAULT_ADDR)
        }
        pub fn new(path: impl AsRef<Path>, addr: u8) -> Result<Self> {
            Ok(Self(I2CActor::new(path, addr)?))
        }
        pub async fn consume_buffer(&mut self) -> Result<usize> {
            let mut ret = 0_usize;
            while self.read::<true>().await?.is_some() {
                ret = ret.wrapping_add(1);
                if ret == 0 { ret = ret.wrapping_add(1); }
            }
            Ok(ret)
        }
        pub async fn read<const ASCII: bool>(&mut self) -> Result<Option<KeypadReadout<{ ASCII }>>> {
            self.0.write(6, 1).await?;
            Ok(KeypadReadout::new(self.0.read(3).await?))
        }
    }

    pub struct Cap1203(I2CActor);
    impl Cap1203 {
        pub async fn new(path: impl AsRef<Path>, addr: u8) -> Result<Self> {
            let mut this = Self(I2CActor::new(path, addr)?);
            this.0.set_pointer(3).await?;
            Ok(this)
        }
        pub async fn read(&mut self) -> Result<u8> {
            Ok(self.0.deref_pointer().await? & 0b111)
        }
    }

    #[allow(clippy::exhaustive_enums)]
    pub enum EncoderReading {
        Position(i16),
        ButtonClick,
    }

    pub struct SparkfunEncoder(I2CActor);
    impl SparkfunEncoder {
        const DEFAULT_ADDR: u8 = 0x3f;
        pub async fn default() -> Result<Self> {
            Self::new(I2C_CHIP_PATH, Self::DEFAULT_ADDR).await
        }
        pub async fn new(path: impl AsRef<Path>, addr: u8) -> Result<Self> {
            let mut this = Self(I2CActor::new(path, addr)?);
            this.0.block_write_u64(5, 0_u64).await?;
            this.clear_flags().await?;
            Ok(this)
        }
        pub async fn color(&mut self, r: u8, g: u8, b: u8) -> Result<()> {
            self.0.block_write_u32(0x0d, u32::from_le_bytes([r, g, b, 0])).await
        }
        async fn clear_flags(&mut self) -> Result<()> {
            self.0.write(1, 0).await
        }
        pub async fn tare(&mut self, pos: i16) -> Result<()> {
            self.0.block_write_u16(5, u16::from_ne_bytes(pos.to_ne_bytes())).await
        }
        pub async fn read(&mut self) -> Result<Option<EncoderReading>> {
            let status = self.0.read(1).await? & 0b101;
            let pressed = status & 0b100 != 0;
            let knob_turned = status & 0b001 != 0;

            let ret = if pressed {
                Some(EncoderReading::ButtonClick)
            } else if knob_turned {
                Some(EncoderReading::Position(i16::from_ne_bytes(self.0.block_read_u16(5).await?.to_ne_bytes())))
            } else {
                None
            };

            if status != 0 {
                self.clear_flags().await?;
            }

            Ok(ret)
        }
    }
}

pub mod ui {

    use regex_automata::DFA;
    use thiserror::Error;

    use super::hal::{self, EncoderReading, SerLcd, SparkfunEncoder, SparkfunKeypad};
    use std::convert::TryInto;
    use std::time::Duration;
    use std::convert::TryFrom;

    #[non_exhaustive]
    #[derive(Error, Debug)]
    pub enum Error {
        #[error("i2c bus fault")]
        I2C(#[from] hal::Error),
        #[error("regex syntax problem")]
        Regex(#[from] regex_automata::Error),
        #[error("menu too large")]
        MenuTooLarge,
    }

    pub type Result<T> = std::result::Result<T, Error>;

    pub async fn menu<S: AsRef<str>>(header: impl AsRef<str>, options: impl AsRef<[S]>, lcd: &mut SerLcd, encoder: &mut SparkfunEncoder, start: usize) -> Result<usize> {

        #[inline]
        #[allow(clippy::integer_arithmetic)]
        #[allow(clippy::integer_division)]
        async fn draw<S: AsRef<str>, const EVERYTHING: bool>(lcd: &mut SerLcd, header: &str, options: &[S], cursor: u16, old_cursor: u16) -> Result<()> {
            let rows: u8 = std::cmp::min(if header.is_empty() { 4 } else { 2 }, std::cmp::min(options.len(), 255).try_into().expect("min(x,255) didn't fit into u8"));
            let rows_ = u16::from(rows);
            let rows__ = usize::from(rows);
            if EVERYTHING || cursor / rows_ != old_cursor / rows_ {
                lcd.clear().await?;
                let first_idx = (cursor / rows_ * rows_).into();
                let lines = options.get(first_idx.. std::cmp::min(first_idx + rows__, options.len())).expect("rustig: min-as-boundscheck didn't work");
                if !header.is_empty() {
                    lcd.write(header, 0, 2, true).await?;
                }
                lcd.write_lines(lines, 4 - rows, 2, true).await?;
            }
            lcd.write(" ", u8::try_from(old_cursor % 4).expect("x%4 didn't fit into u8"), 0, false).await?;
            lcd.write(">", u8::try_from(old_cursor % 4).expect("x%4 didn't fit into u8"), 0, false).await?;
            Ok(())
        }

        let header = header.as_ref();
        let options = options.as_ref();
        if options.is_empty() { return Ok(0); }
        let mut cursor = u16::try_from(start).map_err(|_try_from_int_error| Error::MenuTooLarge)?;
        let options_len = i16::try_from(options.len()).map_err(|_try_from_int_error| Error::MenuTooLarge)?;

        draw::<_, true>(lcd, header, options, cursor, 0).await?;

        encoder.tare(cursor.try_into().map_err(|_try_from_int_error| Error::MenuTooLarge)?).await?;
        Ok(loop {
            match encoder.read().await? {
                Some(EncoderReading::Position(x)) => {
                    let old_cursor = cursor;
                    cursor = periodic_domain(x, options_len);
                    draw::<_, false>(lcd, header, options, cursor, old_cursor).await?;
                }
                Some(EncoderReading::ButtonClick) => break cursor.into(),
                None => {}
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        })
    }

    fn periodic_domain(i: i16, len: i16) -> u16 {
        assert!(len > 0);
        // ((i % len) + len) % len
        // wrapping_rem only wraps in case of i==u16::MAX && len==-1
        i.wrapping_rem(len).wrapping_add(len).wrapping_rem(len).try_into().expect("rustig: cosmic ray")
    }

    pub async fn numeric_entry(lcd: &mut SerLcd, keypad: &mut SparkfunKeypad, name: &str) -> Result<Option<usize>> {
        use super::hal::KeypadReadout;
        let mut buffer = 0_usize;
        lcd.clear().await?;
        lcd.write(name, 0, 0, false).await?;
        let mut i = 0_u16;
        loop {
            match keypad.read::<false>().await? {
                Some(KeypadReadout::Hash) => {
                    break;
                }
                Some(KeypadReadout::Star) => {
                    if buffer == 0 { return Ok(None); }
                    buffer /= 10;
                }
                Some(KeypadReadout::Digit(x)) => {
                    if let (new_buffer, false) = buffer.overflowing_mul(10) {
                        if let (new_buffer, false) = new_buffer.overflowing_add(usize::from(x)) {
                            buffer = new_buffer;
                            lcd.write(&buffer.to_string(), 2, 5, false).await?;
                        }
                    }
                }
                None => {}
            }
            let (i_p, iflag) = i.overflowing_add(1);
            i = i_p;
            if iflag {
                lcd.clear().await?;
                lcd.write(name, 0, 0, false).await?;
                lcd.write(&buffer.to_string(), 2, 5, false).await?;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        Ok(Some(buffer))
    }

    pub async fn digits_entry(lcd: &mut SerLcd, keypad: &mut SparkfunKeypad, name: &str) -> Result<Option<usize>> {
        use super::hal::KeypadReadout;
        let mut buffer = String::with_capacity(20);
        lcd.clear().await?;
        lcd.write(name, 0, 0, false).await?;
        let mut i = 0_u16;
        loop {
            match keypad.read::<false>().await? {
                Some(KeypadReadout::Hash) => {
                    break;
                }
                Some(KeypadReadout::Star) => {
                    if buffer.pop().is_none() { return Ok(None); }
                }
                Some(KeypadReadout::Digit(x)) => {
                    if buffer.len() < buffer.capacity() {
                        if let Some(ch) = char::from_u32(x.into()) {
                            buffer.push(ch);
                            lcd.write(&*buffer, 2, 5, false).await?;
                        }
                    }
                }
                None => {}
            }
            let (i_p, iflag) = i.overflowing_add(1);
            i = i_p;
            if iflag {
                lcd.clear().await?;
                lcd.write(name, 0, 0, false).await?;
                lcd.write(&*buffer, 2, 5, false).await?;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        Ok(Some(buffer.parse().expect("ascii digit string length < 20 didn't form an usize")))
    }

    pub async fn code_confirmation(lcd: &mut SerLcd, keypad: &mut SparkfunKeypad, encoder: &mut SparkfunEncoder, message: &str, rng: &mut oorandom::Rand32) -> Result<bool> {
        use super::hal::KeypadReadout;
        let expectation: u16 = u16::try_from(rng.rand_range(100..10000)).expect("100.10000 didn't fit into u16");
        lcd.clear().await?;
        lcd.write(message, 0, 0, false).await?;
        lcd.write(&format!("THEN TYPE CODE {:04}#", expectation), 3, 0, false).await?;

        let matcher = regex_automata::DenseDFA::new(&format!("{:04}#", expectation))?.to_u16()?;
        let mut state = matcher.start_state();

        let mut iteration = 0_u8;
        let mut cycle = false;
        while !matcher.is_match_state(state) {
            iteration = iteration.wrapping_add(1);
            if iteration == 0 {
                lcd.clear().await?;
                lcd.write(message, 0, 0, false).await?;
                if cycle {
                    lcd.write("OR PRESS * TO ABORT", 3, 0, false).await?;
                } else {
                    lcd.write(&format!("THEN TYPE CODE {:04}#", expectation), 3, 0, false).await?;
                }
                cycle = !cycle;
            }
            match keypad.read::<true>().await? {
                Some(KeypadReadout::Digit(c)) => {
                    // state always comes from the DFA, so elide bounds checks
                    state = unsafe { matcher.next_state_unchecked(state, c) }
                }
                Some(KeypadReadout::Hash) => {
                    // state always comes from the DFA, so elide bounds checks
                    state = unsafe { matcher.next_state_unchecked(state, b'#') }
                }
                Some(KeypadReadout::Star) => {
                    let options = &["No", "Yes"];
                    keypad.consume_buffer().await?;
                    let selection = menu("IS THIS OPERATION\nIMPOSSIBLE?", options, lcd, encoder, 0).await?;
                    if options.get(selection).copied() == Some("Yes") { return Ok(false) }
                    continue;
                }
                None => {}
            }
            if matcher.is_dead_state(state) {
                lcd.write("********************", 3, 0, false).await?;
                state = matcher.start_state();
                keypad.consume_buffer().await?;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok(true)
    }

    pub async fn clear_the_bed(lcd: &mut SerLcd, keypad: &mut SparkfunKeypad, encoder: &mut SparkfunEncoder) -> Result<bool> {
        let mut rng = oorandom::Rand32::new(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("system time is before the epoch").as_secs());
        let messages = &[
            "IDENTIFY THE SATIN\nPOWDER-COATED SHEET,\nMODEL LT-11.",
            "PULL ANY TALL/NARROW\nPARTS OFF OF THE BED\nIF POSSIBLE.",
            "REMOVE SHEET FROM\nBED; BEND TO LOOSEN\nLARGE CONTENTS.",
            "CLEAR THE SHEET WITH\nPLASTIC TOOLS ONLY.",
            "CHECK FOR DEBRIS ON\nTHE SHEET; REMOVE W/\nPLASTIC TOOLS ONLY.",
            "CHECK THE UNDERSIDE\nOF THE SHEET FOR\nSMALL DEBRIS.",
            "CLEAN THE SHEET W/\n90% ISOPROPANOL AND\nMICROFIBER RAGS.",
            "REPLACE THE SHEET,\nAND ENSURE THAT\nALL IS IN ORDER.",
        ];
        for &message in messages {
            if !super::ui::code_confirmation(lcd, keypad, encoder, message, &mut rng).await? {
                lcd.clear().await?;
                lcd.write("OK; PRINTER IS NOW\nMARKED OUT-OF-ORDER\nPENDING MGMT ACTION.\n", 0, 0, false).await?;
                return Ok(false);
            }
        }
        lcd.clear().await?;
        lcd.write("OK, NEW PRINT JOB\nWILL BE STARTED\nAUTOMATICALLY,\nIF QUEUED.", 0, 0, false).await?;
        Ok(true)
    }
}

//pub mod hookif { use structopt::StructOpt; }

pub mod octoprint {

    use serde::{de::IgnoredAny, Deserialize};
    use serde_json::Value;
    use std::path::Path;

    #[derive(Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
    #[serde(rename_all = "lowercase")]
    #[non_exhaustive]
    pub enum FileType {
        MachineCode,
        Model,
        Folder,
    }

    #[derive(Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
    #[serde(rename_all = "lowercase")]
    #[non_exhaustive]
    pub enum FileExt {
        GCode,
        Stl,
    }

    #[derive(Deserialize, Debug, Clone)]
    //#[serde(rename_all="camelCase")]
    #[serde(tag = "type", content = "payload")]
    #[non_exhaustive]
    pub enum Event<'a> {
        PrintCancelled { name: &'a Path, path: &'a Path },
        PrintDone { name: &'a Path, path: &'a Path },
        FileAdded { storage: &'a str, path: &'a Path, name: &'a Path, r#type: (FileType, FileExt) },
        FileRemoved { storage: &'a str, path: &'a Path, name: &'a Path, r#type: (FileType, FileExt) },
        Shutdown,
        Disconnected,
        Error { error: &'a str },
    }

    #[derive(Deserialize, Debug, PartialEq, PartialOrd, Clone)]
    pub struct TempReading {
        actual: f64,
        target: Option<f64>,
    }

    #[derive(Deserialize, Debug, PartialEq, PartialOrd, Clone)]
    struct HistoricTempPoint {
        time: usize,
        tool0: Option<TempReading>,
        bed: Option<TempReading>,
    }

    #[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[serde(rename_all = "camelCase")]
    #[non_exhaustive]
    pub enum PrinterState {
        Operational,
        Paused,
        Printing,
        Pausing,
        Cancelling,
        SdReady,
        Error,
        Ready,
        ClosedOrError,
    }

    #[derive(Deserialize, Debug, Clone)]
    #[serde(rename_all = "camelCase")]
    pub struct PrinterStateDescription {
        text: IgnoredAny,
        pub flags: std::collections::BTreeMap<PrinterState, bool>,
    }

    #[derive(Deserialize, Debug, Clone)]
    #[serde(rename_all = "camelCase")]
    pub struct TickData {
        pub state: PrinterStateDescription,
        job: Value,
        progress: Value,
        current_z: Value,
        offsets: Value,
        temps: Vec<HistoricTempPoint>,
        logs: Value,
        messages: Value,
        resends: Value,
        plugins: Value,
    }
    impl TickData {
        fn latest_bed_temp(&self) -> Option<&TempReading> {
            self.temps.iter().max_by_key(|h| h.time).and_then(|h| h.bed.as_ref())
        }
        pub(crate) fn bed_is_heated(&self) -> Option<bool> {
            self.latest_bed_temp().map(|t| t.target.unwrap_or_default() >= 30.0_f64 || t.actual >= 30.0_f64)
        }
    }

    #[derive(Deserialize, Debug, Clone)]
    #[serde(rename_all = "camelCase")]
    #[non_exhaustive]
    pub struct References<'a> {
        pub resource: &'a str,
        pub download: Option<&'a str>,
        pub model: Option<&'a str>,
    }

    #[derive(Deserialize, Debug, Clone)]
    #[serde(rename_all = "camelCase")]
    #[non_exhaustive]
    pub enum Message<'a> {
        Connected(Value),
        Current(TickData),
        History(TickData),
        Event(#[serde(borrow)] Event<'a>),
        SlicingProgress(Value),
    }

    #[derive(Deserialize, Debug, Clone)]
    #[serde(rename_all = "camelCase")]
    pub struct StatCommon<'a> {
        name: serde::de::IgnoredAny,
        display: serde::de::IgnoredAny,
        #[serde(borrow)]
        pub path: &'a Path,
        pub r#type: FileType,
        type_path: serde::de::IgnoredAny,
    }

    #[derive(Deserialize, Debug, Clone)]
    #[serde(rename_all = "camelCase")]
    #[non_exhaustive]
    pub struct FileInfo<'a> {
        #[serde(flatten)]
        pub info: StatCommon<'a>,
        #[serde(borrow)]
        pub hash: Option<&'a str>,
        pub size: Option<usize>,
        pub date: Option<usize>,
        pub origin: &'a str,
        #[serde(borrow)]
        pub refs: References<'a>,
        pub gcode_analysis: serde::de::IgnoredAny,
    }

    #[derive(Deserialize, Debug, Clone)]
    #[serde(rename_all = "camelCase")]
    #[non_exhaustive]
    pub struct FolderInfo<'a> {
        #[serde(flatten)]
        pub info: StatCommon<'a>,
        #[serde(borrow)]
        pub children: Vec<Stat<'a>>,
        pub size: Option<usize>,
    }

    #[derive(Deserialize, Debug, Clone)]
    #[serde(rename_all = "camelCase")]
    #[serde(untagged)]
    #[non_exhaustive]
    pub enum Stat<'a> {
        FileInfo(#[serde(borrow)] FileInfo<'a>),
        FolderInfo(#[serde(borrow)] FolderInfo<'a>),
    }

    impl<'a> Stat<'a> {
        #[must_use]
        pub fn as_file_info(&self) -> Option<&FileInfo> {
            if let Self::FileInfo(ref v) = *self {
                Some(v)
            } else {
                None
            }
        }


        pub fn try_into_file_info(self) -> Result<FileInfo<'a>, Self> {
            if let Self::FileInfo(v) = self {
                Ok(v)
            } else {
                Err(self)
            }
        }

        #[must_use]
        pub fn as_folder_info(&self) -> Option<&FolderInfo> {
            if let Self::FolderInfo(ref v) = *self {
                Some(v)
            } else {
                None
            }
        }

        pub fn try_into_folder_info(self) -> Result<FolderInfo<'a>, Self> {
            if let Self::FolderInfo(v) = self {
                Ok(v)
            } else {
                Err(self)
            }
        }
    }

    #[derive(Deserialize, Debug, Clone)]
    #[serde(rename_all = "camelCase")]
    pub struct AbridgedStat<'a> {
        name: serde::de::IgnoredAny,
        display: serde::de::IgnoredAny,
        #[serde(borrow)]
        pub path: &'a Path,
        pub origin: &'a str,
        #[serde(borrow)]
        pub refs: References<'a>,
    }
}

pub mod webif {

    use super::octoprint;
    use futures_util::{stream::FusedStream, Sink, SinkExt, Stream, StreamExt, FutureExt};
    use serde::Deserialize;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;
    use thiserror::Error;
    use tokio::sync::{RwLock, watch};
    use tokio_tungstenite::tungstenite;

    #[non_exhaustive]
    #[derive(Error, Debug)]
    pub enum Error {
        #[error("bad API key")]
        BadApiKey,
        #[error("web request error: {0}")]
        Reqwest(#[from] reqwest::Error),
        #[error("websocket error: {0}")]
        Websockets(#[from] tungstenite::Error),
        #[error("serde error: {0}")]
        Serde(#[from] serde_json::Error),
        #[error("i2c comms error: {0}")]
        I2C(#[from] super::ui::Error),
        //#[error(transparent)]
        //Other(#[from] Box<dyn std::error::Error + 'static>),
    }

    async fn process_octoprint_websocket_message<'buffer>(
        ws_stream: &mut (impl Sink<tungstenite::Message, Error = tungstenite::Error> + Unpin), message: tungstenite::Result<tungstenite::Message>, buffer: &'buffer mut String,
    ) -> Result<Option<octoprint::Message<'buffer>>, Error> {
        use tokio_tungstenite::tungstenite::{Error::*, Message::*};
        Ok(match message {
            Ok(Text(t)) => {
                *buffer = t;
                let buffer = &buffer[..]; // drop the mut
                serde_json::from_str(&buffer).ok()
            }
            Ok(Ping(m)) => {
                ws_stream.send(Pong(m)).await?;
                None
            }
            Ok(Close(_)) => {
                ws_stream.close().await?;
                None
            }
            Err(SendQueueFull(_)) => unreachable!(),
            x => {
                x?;
                None
            }
        })
    }

    pub async fn login_to_octoprint<'buffer>(
        token: &str, buffer: &'buffer mut String,
    ) -> Result<(tokio_tungstenite::WebSocketStream<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>, octoprint::TickData), Error> {
        #[derive(Deserialize)]
        struct LoginResponse<'a> {
            name: &'a str,
            session: &'a str,
        }
        let client = reqwest::Client::builder().timeout(Duration::from_secs(30)).build()?;
        let resp = client.post(make_url("login", "").await).json(&serde_json::json!({"passive": true})).bearer_auth(token).send().await?;
        if resp.status() == reqwest::StatusCode::FORBIDDEN {
            return Err(Error::BadApiKey);
        }
        let buf = resp.text().await?;
        let LoginResponse { name, session } = serde_json::from_str(&buf)?;
        let mut ws_stream = tokio_tungstenite::connect_async(make_ws_url().await).await?.0;

        for m in std::array::IntoIter::new([serde_json::json!({ "auth": format!("{}:{}", name, session) }), serde_json::json!({ "throttle": 118_u8 })])
            .map(|v| tungstenite::Message::text(v.to_string()))
        {
            ws_stream.feed(m).await?;
        }

        ws_stream.flush().await?;

        let ret = 'firstdata: loop {
            while let Some(message) = ws_stream.next().await {
                if let Some(octoprint::Message::History(h)) = process_octoprint_websocket_message(&mut ws_stream, message, buffer).await? {
                    break 'firstdata h
                }
            }
            panic!("octoprint quit before sending us the History message");
        };
        Ok((ws_stream, ret))
    }

    async fn make_ws_url() -> reqwest::Url {
        let mut url = make_url("", "").await;
        url.set_path("sockjs/websocket");
        url.set_scheme("ws").expect("cosmic ray");
        url
    }

    async fn make_url(q: impl AsRef<Path>, p: impl AsRef<Path>) -> reqwest::Url {
        fn componentize(p: &Path) -> impl Iterator<Item = &str> {
            p.components().filter_map(|c| if let std::path::Component::Normal(x) = c { Some(x).and_then(std::ffi::OsStr::to_str) } else { None })
        }

        static BASE: tokio::sync::OnceCell<reqwest::Url> = tokio::sync::OnceCell::const_new();
        let mut url = BASE.get_or_init(|| futures_util::future::ready(reqwest::Url::parse("http://octopi.local/api").expect("internal url syntax error"))).await.clone();

        let p = p.as_ref();
        let q = q.as_ref();

        url.path_segments_mut().expect("cosmic ray: cannot be a base").pop_if_empty().extend(componentize(q)).extend(componentize(p));

        url
    }

    async fn start_print(token: &'static str, client: &reqwest::Client, path: impl AsRef<Path>) -> Result<PathBuf, Error> {

        let response_buffer = client.post(make_url("files/local", path).await).bearer_auth(token).json(&serde_json::json!({"command": "move", "destination": "/"})).send().await?.error_for_status()?.text().await?;
        let response_de: octoprint::AbridgedStat = serde_json::from_str(&response_buffer)?;
        client.post(response_de.refs.resource).bearer_auth(token).json(&serde_json::json!({"command": "select", "print": true})).send().await?.error_for_status()?;

        Ok(response_de.path.to_owned())
    }

    pub async fn do_stuff(token: &'static str) -> Result<(), Error> {
        let mut buffer = Default::default();

        let mut lcd = super::hal::SerLcd::default().map_err(super::ui::Error::from)?;
        let mut keypad = super::hal::SparkfunKeypad::default().map_err(super::ui::Error::from)?;
        let mut encoder = super::hal::SparkfunEncoder::default().await.map_err(super::ui::Error::from)?;

        let (ws_stream, first_data) = login_to_octoprint(token, &mut buffer).await?;

        let mut buffer = Default::default();

        let (data_tx, data_rx) = watch::channel::<octoprint::TickData>(first_data);
        let (is_heated_tx, mut is_heated_rx) = watch::channel(false);

        let octoprint_rest_client = reqwest::Client::new();

        let mut queue = Arc::new(RwLock::new({
            let response_buffer = octoprint_rest_client.get(make_url("files/local", "queue").await).bearer_auth(token).send().await?.error_for_status()?.text().await?;
            let response_de: octoprint::Stat = serde_json::from_str(&response_buffer)?;
            let response_de = response_de.try_into_folder_info().expect("queue is not a folder");
            response_de.children.iter().filter_map(octoprint::Stat::as_file_info).map(|x| x.info.path.to_path_buf()).collect::<Vec<PathBuf>>()
        }));

        let queue_path = std::path::Path::new("queue");

        let mut print_complete_flag = false;
        let mut printer_ready_flag = false;

        let (mut ws_sink, mut ws_stream) = ws_stream.split();

        let mut subtask_handles = std::array::IntoIter::new([
            tokio::spawn(heat_translator(data_rx.clone(), is_heated_tx)),

            tokio::spawn({let queue = Arc::clone(&queue); async move {
                while let Some(message) = ws_stream.next().await {
                    if let Some(message) = process_octoprint_websocket_message(&mut ws_sink, message, &mut buffer).await? {
                        use octoprint::{Message::*, Event::*};
                        match message {
                            Event(FileAdded { storage: "local", path, name, r#type: (octoprint::FileType::MachineCode, _) })
                                if path.components().eq(std::iter::once(std::path::Component::Normal(std::ffi::OsStr::new("queue"))))
                                    => {
                                        let new_file = queue_path.join(name);
                                        queue.write().await.insert(0, new_file); },
                            Event(FileRemoved { storage: "local", path, name, r#type: (octoprint::FileType::MachineCode, _) })
                                if path.components().eq(std::iter::once(std::path::Component::Normal(std::ffi::OsStr::new("queue"))))
                                    => {
                                        let old_file = queue_path.join(name);
                                        queue.write().await.retain(|x| old_file.cmp(x) != std::cmp::Ordering::Equal); },
                            Event(FileAdded { .. }) | Event(FileRemoved { .. }) => {},
                            Event(PrintDone { .. }) => { print_complete_flag = true; },
                            Event(Shutdown) => break,
                            Event(PrintCancelled { .. }) => { printer_ready_flag = false; },
                            Event(Disconnected) => break,
                            Event(Error { error }) => { printer_ready_flag = false; },
                            Current(m) => { if data_tx.send(m).is_err() { break; } },
                            History(_) | Connected(_) | SlicingProgress(_) => {}
                        }
                    }
                }
                Ok(())
            }}),
        ])
        .collect::<futures_util::stream::FuturesUnordered<_>>();

        let ret = loop {
            futures_util::select_biased! {
                // biased;
                // todo: Ctrl-C et al
                r = subtask_handles.select_next_some() => { break Ok(r.expect("panic propagation")?); },
                r = is_heated_rx.changed().fuse() => {
                    if r.is_err() { break Ok(()); }
                    if print_complete_flag && !*is_heated_rx.borrow() {
                        print_complete_flag = false;
                        printer_ready_flag = super::ui::clear_the_bed(&mut lcd, &mut keypad, &mut encoder).await?;
                        if printer_ready_flag && data_rx.borrow().state.flags.get(&octoprint::PrinterState::Operational).copied().unwrap_or_default() {
                            if let Some(p) = queue.write().await.pop() {
                                start_print(token, &octoprint_rest_client, p).await?;
                            }
                        }
                    }
                },
                complete => { break Ok(()); }
            };
            tokio::task::yield_now().await;
        };
        while let Some(()) = subtask_handles.next().await.map(|r| r.expect("panic propagation")).transpose()? {}
        ret
    }

    async fn heat_translator(mut data_rx: watch::Receiver<octoprint::TickData>, is_heated_tx: watch::Sender<bool>) -> Result<(), Error> {
        let mut heated = false;
        while data_rx.changed().await.is_ok() {
            if data_rx.borrow().bed_is_heated() == Some(!heated) {
                heated = !heated;
                if is_heated_tx.send(heated).is_err() {
                    break;
                }
            }
        }
        Ok(())
    }
}
