#![warn(clippy::all)]
#![warn(clippy::todo)]

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
            fn block_write_noreg_const_ld(&mut self, content: [u8; 32], len: u8) -> Result<()> {
                let bytes = &content[..len as usize]; //content.splitn(2, |&x|x==0).next().unwrap_or_default();
                self.dev.write(self.addr, bytes)
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
                                    // The `let _ =` ignores any errors when sending.
                                    //
                                    // This can happen if the `select!` macro is used
                                    // to cancel waiting for the response.
                                    let _ = respond_to.send(ret);
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
                            let _ = self.sender.send(msg).await;
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
            BlockWriteNoReg32LD block_write_noreg_arr32_ld(content: [u8; 32], len: u8) -> Result<()> { self.dev.block_write_noreg_const_ld(content, len) },
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
    use std::path::Path;

    pub use blocking::{Error, I2CActor, Result};

    pub enum LcdBrightness {
        R(u8),
        G(u8),
        B(u8),
    }
    impl From<LcdBrightness> for u8 {
        fn from(this: LcdBrightness) -> Self {
            const BEGIN: u8 = 128;
            const LEN: u8 = 30;
            #[inline]
            fn rerange(x: u8) -> u8 {
                ((((x as u16) << 2) / 35) as u8).clamp(0, LEN - 1)
            }
            use LcdBrightness::*;
            match this {
                R(r) => rerange(r) + BEGIN,
                G(g) => rerange(g) + BEGIN + LEN,
                B(b) => rerange(b) + BEGIN + LEN + LEN,
            }
        }
    }

    pub struct SerLcd(I2CActor);
    impl SerLcd {
        pub fn new(path: impl AsRef<Path>, addr: u8) -> Result<Self> {
            Ok(Self(I2CActor::new(path, addr)?))
        }
        #[inline]
        fn lineno(line: u8, column: u8) -> u8 {
            let column = column.clamp(0, 19);
            128 + column + 0x20 * (line & 0b10) + 0x64 * (line & 0b01)
        }
        #[inline]
        pub async fn write(&mut self, text: &str, line: u8, column: u8, everycolumn: bool) -> Result<()> {
            self.write_lines(text.lines(), line, column, everycolumn).await
        }
        pub async fn write_lines(&mut self, lines: impl IntoIterator<Item = impl AsRef<str>>, line: u8, column: u8, everycolumn: bool) -> Result<()> {
            let line = line;
            let column = column.clamp(0, 19);
            for (ret, len) in lines.into_iter().enumerate().map(|(i, s)| {
                let line = line + (i % 256) as u8;
                let column = if i == 0 || everycolumn { column } else { 0 };
                Self::format_line(s.as_ref(), line, column)
            }) {
                self.0.block_write_noreg_arr32_ld(ret, len).await?;
            }
            Ok(())
        }
        #[inline]
        fn format_line(text: &str, line: u8, column: u8) -> ([u8; 32], u8) {
            use std::io::Write;
            let mut ret = [0u8; 32];
            ret[0] = 254;
            ret[1] = Self::lineno(line, column);

            let s = text.as_bytes();
            let written_len = (&mut ret[2..22]).write(s).expect("rustig: cosmic ray");
            let len = written_len + 2;

            (ret, len as u8)
        }
        pub async fn clear(&mut self) -> Result<()> {
            self.0.write(b'|', b'-').await
        }
        pub async fn set_brightness(&mut self, brightness: LcdBrightness) -> Result<()> {
            self.0.write(b'|', brightness.into()).await
        }
    }

    pub struct SparkfunKeypad(I2CActor);
    impl SparkfunKeypad {
        pub fn new(path: impl AsRef<Path>, addr: u8) -> Result<Self> {
            Ok(Self(I2CActor::new(path, addr)?))
        }
        pub async fn consume_buffer(&mut self) -> Result<usize> {
            let mut ret = 0usize;
            while let Some(_) = self.read().await? {
                ret = ret.wrapping_add(1);
            }
            Ok(ret)
        }
        pub async fn read(&mut self) -> Result<Option<char>> {
            self.0.write(6, 1).await?;
            Ok(Some(self.0.read(3).await? as char).filter(|&c| c != '\0'))
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

    pub enum EncoderReading {
        Position(i16),
        ButtonClick,
    }

    pub struct SparkfunEncoder(I2CActor);
    impl SparkfunEncoder {
        pub async fn new(path: impl AsRef<Path>, addr: u8) -> Result<Self> {
            let mut this = Self(I2CActor::new(path, addr)?);
            this.0.block_write_u64(5, 0u64).await?;
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
            self.0.block_write_u16(5, pos as u16).await
        }
        pub async fn read(&mut self) -> Result<Option<EncoderReading>> {
            let status = self.0.read(1).await? & 0b101;
            let pressed = status & 0b100 != 0;
            let knob_turned = status & 0b001 != 0;

            let ret = if pressed {
                Some(EncoderReading::ButtonClick)
            } else if knob_turned {
                Some(EncoderReading::Position(self.0.block_read_u16(5).await? as i16))
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
    use std::time::Duration;

    #[derive(Error, Debug)]
    pub enum Error {
        #[error("i2c bus fault")]
        I2C(#[from] hal::Error),
        #[error("regex syntax problem")]
        Regex(#[from] regex_automata::Error),
    }

    pub type Result<T> = std::result::Result<T, Error>;

    pub async fn menu<S: AsRef<str>>(header: impl AsRef<str>, options: impl AsRef<[S]>, lcd: &mut SerLcd, encoder: &mut SparkfunEncoder, start: usize) -> Result<usize> {
        let header = header.as_ref();
        let options = options.as_ref();
        let mut cursor = start as i16;

        #[inline(always)]
        async fn draw<S: AsRef<str>, const EVERYTHING: bool>(lcd: &mut SerLcd, header: &str, options: &[S], cursor: i16, old_cursor: i16) -> Result<()> {
            let rows: u8 = if header.is_empty() { 4 } else { 2 };
            let rows_ = rows as i16;
            let rows__ = rows as usize;
            if EVERYTHING || cursor / rows_ != old_cursor / rows_ {
                lcd.clear().await?;
                let first_idx = (cursor / rows_ * rows_) as u16 as usize;
                let lines = &options[first_idx..first_idx + rows__];
                if !header.is_empty() {
                    lcd.write(header, 0, 2, true).await?;
                }
                lcd.write_lines(lines, 4 - rows, 2, true).await?;
            }
            lcd.write(" ", (old_cursor % 4) as u8, 0, false).await?;
            lcd.write(">", (/**/cursor % 4) as u8, 0, false).await?;
            Ok(())
        }
        draw::<_, true>(lcd, header, options, cursor, 0).await?;

        encoder.tare(start as i16).await?;
        Ok(loop {
            match encoder.read().await? {
                Some(EncoderReading::Position(x)) => {
                    let old_cursor = cursor;
                    cursor = periodic_domain(x, options.len() as i16);
                    draw::<_, false>(lcd, header, options, cursor, old_cursor).await?;
                }
                Some(EncoderReading::ButtonClick) => break cursor as u16 as usize,
                None => {}
            }
            tokio::time::sleep(Duration::from_millis(1)).await
        })
    }

    fn periodic_domain(i: i16, len: i16) -> i16 {
        let rem = i % len;
        if rem < 0 {
            len - rem
        } else {
            rem
        }
    }

    pub async fn numeric_entry(lcd: &mut SerLcd, keypad: &mut SparkfunKeypad, name: &str) -> Result<usize> {
        let mut buffer = String::new();
        let max_buffer_len = (usize::MAX as f64).log10() as usize;
        lcd.clear().await?;
        lcd.write(name, 0, 0, false).await?;
        let mut i = 0u16;
        loop {
            match keypad.read().await? {
                Some('#') => {
                    break;
                }
                Some('*') => {
                    buffer.pop();
                }
                Some(x) if x.is_ascii_digit() && buffer.len() < max_buffer_len => {
                    buffer.push(x);
                    lcd.write(&buffer, 2, 5, false).await?;
                }
                _ => {}
            }
            let (i_p, iflag) = i.overflowing_add(1);
            i = i_p;
            if iflag {
                lcd.clear().await?;
                lcd.write(name, 0, 0, false).await?;
                lcd.write(&buffer, 2, 5, false).await?;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        Ok(buffer.parse().unwrap())
    }

    pub async fn code_confirmation(lcd: &mut SerLcd, keypad: &mut SparkfunKeypad, message: &str, rng: &mut oorandom::Rand32) -> Result<()> {
        let expectation: u16 = rng.rand_range(1000..10000) as u16;
        lcd.clear().await?;
        lcd.write(message, 0, 0, false).await?;
        lcd.write(&format!("THEN TYPE CODE: {}", expectation), 3, 0, false).await?;
        let mut last_refresh = Some(std::time::Instant::now());

        let matcher = match regex_automata::DenseDFA::new(&expectation.to_string())?.to_u16()? {
            regex_automata::DenseDFA::PremultipliedByteClass(d) => Box::new(d),
            _ => unreachable!(),
        };
        let mut state = matcher.start_state();

        while !matcher.is_match_state(state) {
            if last_refresh.map(|i| i.elapsed().as_secs() > 5).unwrap_or(true) {
                lcd.clear().await?;
                lcd.write(message, 0, 0, false).await?;
                lcd.write(&format!("then type code {}", expectation), 3, 0, false).await?;
                last_refresh = Some(std::time::Instant::now())
            }
            if let Some(c) = keypad.read().await? {
                // state always comes from the DFA, so elide bounds checks
                state = unsafe { matcher.next_state_unchecked(state, c as u8) };
            }
            if matcher.is_dead_state(state) {
                last_refresh.take();
                lcd.write("********************", 3, 0, false).await?;
                state = matcher.start_state();
                keypad.consume_buffer().await?;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        Ok(())
    }

    pub async fn clear_the_bed() -> Result<()> {
        let mut lcd = SerLcd::new("/dev/i2c-1", 0x72)?;
        let mut keypad = SparkfunKeypad::new("/dev/i2c-1", 0x4b)?;
        let mut rng = oorandom::Rand32::new(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("system time is in the past").as_secs());
        super::ui::code_confirmation(&mut lcd, &mut keypad, "IDENTIFY THE SATIN\nPOWDER-COATED SHEET,\nTHEN ENTER CODE.", &mut rng).await?;
        super::ui::code_confirmation(&mut lcd, &mut keypad, "PULL ANY TALL/NARROW\nPARTS OFF OF THE BED\nIF POSSIBLE.", &mut rng).await?;
        super::ui::code_confirmation(&mut lcd, &mut keypad, "REMOVE SHEET FROM\nBED; BEND TO LOOSEN\nLARGE CONTENTS.", &mut rng).await?;
        super::ui::code_confirmation(&mut lcd, &mut keypad, "CLEAR THE SHEET WITH\nPLASTIC TOOLS ONLY.", &mut rng).await?;
        super::ui::code_confirmation(&mut lcd, &mut keypad, "CHECK FOR DEBRIS ON\nTHE SHEET; REMOVE W/\nPLASTIC TOOLS ONLY.", &mut rng).await?;
        super::ui::code_confirmation(&mut lcd, &mut keypad, "CHECK THE UNDERSIDE\nOF THE SHEET FOR\nSMALL DEBRIS.", &mut rng).await?;
        super::ui::code_confirmation(&mut lcd, &mut keypad, "CLEAN THE SHEET W/\n90% ISOPROPANOL AND\nMICROFIBER RAGS.", &mut rng).await?;
        super::ui::code_confirmation(&mut lcd, &mut keypad, "REPLACE THE SHEET,\nAND ENSURE THAT\nALL IS IN ORDER.", &mut rng).await?;
        lcd.clear().await?;
        lcd.write("OK, NEW PRINT JOB\nWILL BE STARTED\nAUTOMATICALLY,\nIF QUEUED.", 0, 0, false).await?;
        Ok(())
    }
}

//pub mod hookif { use structopt::StructOpt; }

pub mod octoprint {
    use serde::{de::IgnoredAny, Deserialize};
    use serde_json::Value;
    use std::path::Path;

    #[derive(Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
    #[serde(rename_all = "lowercase")]
    pub enum FileType {
        MachineCode,
        Model,
        Folder,
    }

    #[derive(Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
    #[serde(rename_all = "lowercase")]
    pub enum FileExt {
        GCode,
        Stl,
    }

    #[derive(Deserialize, Debug, Clone)]
    //#[serde(rename_all="camelCase")]
    #[serde(tag = "type", content = "payload")]
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
            self.latest_bed_temp().map(|t| t.target.unwrap_or_default() >= 30.0 || t.actual >= 30.0)
        }
    }

    #[derive(Deserialize, Debug, Clone)]
    #[serde(rename_all = "camelCase")]
    pub struct References<'a> {
        pub resource: &'a str,
        pub download: Option<&'a str>,
        pub model: Option<&'a str>,
    }

    #[derive(Deserialize, Debug, Clone)]
    #[serde(rename_all = "camelCase")]
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
    pub enum Stat<'a> {
        FileInfo(#[serde(borrow)] FileInfo<'a>),
        FolderInfo(#[serde(borrow)] FolderInfo<'a>),
    }

    impl<'a> Stat<'a> {
        pub fn as_file_info(&self) -> Option<&FileInfo> {
            if let Self::FileInfo(v) = self {
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

        pub fn as_folder_info(&self) -> Option<&FolderInfo> {
            if let Self::FolderInfo(v) = self {
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
    use futures_util::{stream::FusedStream, Sink, SinkExt, Stream, StreamExt};
    use serde::Deserialize;
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use thiserror::Error;
    use tokio::sync::watch;
    use tokio_tungstenite::tungstenite;

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
        let client = reqwest::Client::builder().timeout(Duration::from_secs(30)).build()?;
        let resp = client.post(make_url("login", "").await).json(&serde_json::json!({"passive": true})).bearer_auth(token).send().await?;
        #[derive(Deserialize)]
        struct LoginResponse<'a> {
            name: &'a str,
            session: &'a str,
        }
        if resp.status() == reqwest::StatusCode::FORBIDDEN {
            return Err(Error::BadApiKey);
        }
        let buf = resp.text().await?;
        let LoginResponse { name, session } = serde_json::from_str(&buf)?;
        let mut ws_stream = tokio_tungstenite::connect_async(make_ws_url().await).await?.0;

        for m in std::array::IntoIter::new([serde_json::json!({ "auth": format!("{}:{}", name, session) }), serde_json::json!({ "throttle": 118 })])
            .map(|v| tungstenite::Message::text(v.to_string()))
        {
            ws_stream.feed(m).await?;
        }

        ws_stream.flush().await?;

        let ret = 'firstdata: loop {
            while let Some(message) = ws_stream.next().await {
                match process_octoprint_websocket_message(&mut ws_stream, message, buffer).await? {
                    Some(octoprint::Message::History(h)) => break 'firstdata h,
                    _ => continue,
                }
            }
            panic!();
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
        static BASE: tokio::sync::OnceCell<reqwest::Url> = tokio::sync::OnceCell::const_new();
        let mut url = BASE.get_or_init(|| futures_util::future::ready(reqwest::Url::parse("http://octopi.local/api").expect("internal url syntax error"))).await.clone();

        let p = p.as_ref();
        let q = q.as_ref();

        fn componentize(p: &Path) -> impl Iterator<Item = &str> {
            p.components().filter_map(|c| if let std::path::Component::Normal(x) = c { Some(x).and_then(std::ffi::OsStr::to_str) } else { None })
        }

        url.path_segments_mut().expect("cosmic ray: cannot be a base").pop_if_empty().extend(componentize(q)).extend(componentize(p));

        url
    }

    pub async fn print_queueing(
        token: &str, add_rx: impl Stream<Item = PathBuf>, rm_rx: impl Stream<Item = PathBuf>, shift_rx: impl Stream<Item = tokio::sync::oneshot::Sender<String>>,
        tick_rx: tokio::sync::watch::Receiver<octoprint::TickData>,
    ) -> Result<(), Error> {
        futures_util::pin_mut!(add_rx);
        futures_util::pin_mut!(rm_rx);
        futures_util::pin_mut!(shift_rx);
        futures_util::pin_mut!(tick_rx);

        let client = reqwest::Client::new();

        let mut queue: Vec<PathBuf> = {
            let response_buffer = client.get(make_url("files/local", "queue").await).bearer_auth(token).send().await?.error_for_status()?.text().await?;
            let response_de: octoprint::Stat = serde_json::from_str(&response_buffer)?;
            let response_de = response_de.try_into_folder_info().expect("queue is not a folder");
            response_de.children.iter().filter_map(|x| x.as_file_info()).map(|x| x.info.path.to_path_buf()).collect()
        };

        let queue_path = std::path::Path::new("queue");

        loop {
            tokio::select! {
                biased;
                Some(new_file) = add_rx.next() => {
                    queue.insert(0, queue_path.join(new_file));
                }
                Some(old_file) = rm_rx.next() => {
                    let old_file = queue_path.join(old_file);
                    queue.retain(|x| old_file.cmp(x) != std::cmp::Ordering::Equal);
                }
                Some(tx) = shift_rx.next(), if !queue.is_empty() && tick_rx.borrow().state.flags.get(&octoprint::PrinterState::Operational).copied().unwrap_or_default() => {
                    let response_buffer = client.post(make_url("files/local", queue.pop().expect("cosmic ray")).await).bearer_auth(token).json(&serde_json::json!({"command": "move", "destination": "/"})).send().await?.error_for_status()?.text().await?;
                    let response_de: octoprint::AbridgedStat = serde_json::from_str(&response_buffer)?;
                    client.post(response_de.refs.resource).bearer_auth(token).json(&serde_json::json!({"command": "select", "print": true})).send().await?.error_for_status()?;

                    if tx.send(response_de.path.to_string_lossy().into_owned()).is_err() { break Ok(()) }
                }
                else => break Ok(())
            }
        }
    }

    pub async fn do_stuff(token: &'static str) -> Result<(), Error> {
        let mut buffer = Default::default();

        let (ws_stream, first_data) = login_to_octoprint(token, &mut buffer).await?;

        let mut buffer = Default::default();

        let (data_tx, data_rx) = watch::channel::<octoprint::TickData>(first_data);
        let (is_heated_tx, mut is_heated_rx) = watch::channel(false);

        let (add_tx, add_rx) = tokio::sync::mpsc::unbounded_channel();
        let (rm_tx, rm_rx) = tokio::sync::mpsc::unbounded_channel();
        let (shift_tx, shift_rx) = tokio::sync::mpsc::unbounded_channel();

        let mut print_complete_flag = false;

        let mut subtask_handles = std::array::IntoIter::new([
            tokio::spawn(heat_translator(data_rx.clone(), is_heated_tx)),
            tokio::spawn(print_queueing(
                token,
                tokio_stream::wrappers::UnboundedReceiverStream::new(add_rx),
                tokio_stream::wrappers::UnboundedReceiverStream::new(rm_rx),
                tokio_stream::wrappers::UnboundedReceiverStream::new(shift_rx),
                data_rx.clone(),
            )),
        ])
        .collect::<futures_util::stream::FuturesUnordered<_>>();

        let (mut ws_sink, ws_stream) = ws_stream.split();

        let mut ws_stream = ws_stream.fuse();

        let ret = loop {
            tokio::select! {
                biased;
                // todo: Ctrl-C et al
                r = subtask_handles.select_next_some(), if !subtask_handles.is_terminated() || break Ok(()) => { break Ok(r.unwrap()?); }
                message = ws_stream.select_next_some(), if !ws_stream.is_terminated() => {
                    if let Some(message) = process_octoprint_websocket_message(&mut ws_sink, message, &mut buffer).await? {
                        use octoprint::{Message::*, Event::*};
                        match message {
                            Event(FileAdded { storage: "local", path, name, r#type: (octoprint::FileType::MachineCode, _) }) if path.components().cmp(std::iter::once(std::path::Component::Normal(std::ffi::OsStr::new("queue")))) == std::cmp::Ordering::Equal => if add_tx.send(path.join(name)).is_err() { break Ok(()); },
                            Event(FileRemoved { storage: "local", path, name, r#type: (octoprint::FileType::MachineCode, _) }) if path.components().cmp(std::iter::once(std::path::Component::Normal(std::ffi::OsStr::new("queue")))) == std::cmp::Ordering::Equal => if rm_tx.send(path.join(name)).is_err() { break Ok(()); },
                            Event(FileAdded { .. }) | Event(FileRemoved { .. })=> {},
                            Event(PrintDone { .. }) => { print_complete_flag = true; },
                            Event(Shutdown) => break Ok(()),
                            Event(PrintCancelled { .. }) => todo!(),
                            Event(Disconnected) => todo!(),
                            Event(Error { error }) => todo!(),
                            Current(m) => { if data_tx.send(m).is_err() { break Ok(()); } },
                            History(_) | Connected(_) | SlicingProgress(_) => {}
                        }
                    }
                }
                Ok(()) = is_heated_rx.changed() => if print_complete_flag && !*is_heated_rx.borrow() {
                    print_complete_flag = false;
                    super::ui::clear_the_bed().await?;
                }
                else { break Ok(()); }
            }
            tokio::task::yield_now().await;
        };
        while !subtask_handles.is_terminated() {
            subtask_handles.select_next_some().await.unwrap()?;
        }
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
