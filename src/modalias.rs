#[derive(Debug, PartialEq)]
pub enum Bus {
    Any,
    PCI,
    ISAPnP,
    USB,
    HIL,
    Bluetooth,
    Virtual,
    ISA,
    I8042,
    XtKbd,
    Rs232,
    GamePort,
    ParPort,
    Amiga,
    ADB,
    I2C,
    Host,
    GSC,
    Atari,
    SPI,
    RMI,
    CEC,
    IntelIshtp,
    AmdSfh,
}

impl TryFrom<usize> for Bus {
    type Error = &'static str;

    fn try_from(sz: usize) -> Result<Self, Self::Error> {
        match sz {
            0x00 => Ok(Bus::Any),
            0x01 => Ok(Bus::PCI),
            0x02 => Ok(Bus::ISAPnP),
            0x03 => Ok(Bus::USB),
            0x04 => Ok(Bus::HIL),
            0x05 => Ok(Bus::Bluetooth),
            0x06 => Ok(Bus::Virtual),
            0x10 => Ok(Bus::ISA),
            0x11 => Ok(Bus::I8042),
            0x12 => Ok(Bus::XtKbd),
            0x13 => Ok(Bus::Rs232),
            0x14 => Ok(Bus::GamePort),
            0x15 => Ok(Bus::ParPort),
            0x16 => Ok(Bus::Amiga),
            0x17 => Ok(Bus::ADB),
            0x18 => Ok(Bus::I2C),
            0x19 => Ok(Bus::Host),
            0x1A => Ok(Bus::GSC),
            0x1B => Ok(Bus::Atari),
            0x1C => Ok(Bus::SPI),
            0x1D => Ok(Bus::RMI),
            0x1E => Ok(Bus::CEC),
            0x1F => Ok(Bus::IntelIshtp),
            0x20 => Ok(Bus::AmdSfh),
            _ => Err("Invalid bus type"),
        }
    }
}

impl From<&Bus> for usize {
    fn from(bus: &Bus) -> Self {
        match bus {
            Bus::Any => 0x00,
            Bus::PCI => 0x01,
            Bus::ISAPnP => 0x02,
            Bus::USB => 0x03,
            Bus::HIL => 0x04,
            Bus::Bluetooth => 0x05,
            Bus::Virtual => 0x06,
            Bus::ISA => 0x10,
            Bus::I8042 => 0x11,
            Bus::XtKbd => 0x12,
            Bus::Rs232 => 0x13,
            Bus::GamePort => 0x14,
            Bus::ParPort => 0x15,
            Bus::Amiga => 0x16,
            Bus::ADB => 0x17,
            Bus::I2C => 0x18,
            Bus::Host => 0x19,
            Bus::GSC => 0x1A,
            Bus::Atari => 0x1B,
            Bus::SPI => 0x1C,
            Bus::RMI => 0x1D,
            Bus::CEC => 0x1E,
            Bus::IntelIshtp => 0x1F,
            Bus::AmdSfh => 0x20,
        }
    }
}

impl std::fmt::UpperHex for Bus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val: usize = self.into();
        std::fmt::UpperHex::fmt(&val, f)
    }
}

impl std::fmt::LowerHex for Bus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val: usize = self.into();
        std::fmt::LowerHex::fmt(&val, f)
    }
}

#[derive(Debug)]
pub struct Modalias {
    pub bus: Bus,
    pub group: u32,
    pub vid: u32,
    pub pid: u32,
}

impl Modalias {
    pub fn from_str(modalias: &str) -> std::io::Result<Self> {
        /* strip out the "hid:" prefix from the modalias */
        let modalias = modalias.trim_start_matches("hid:");

        if modalias.len() != 28 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid modalias '{}'", modalias),
            ));
        }

        let econvert = |_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid modalias '{}'", modalias),
            )
        };

        let bus =
            Bus::try_from(usize::from_str_radix(&modalias[1..5], 16).map_err(econvert)?).unwrap();
        let group = u32::from_str_radix(&modalias[6..10], 16).map_err(econvert)?;
        let vid = u32::from_str_radix(&modalias[11..19], 16).map_err(econvert)?;
        let pid = u32::from_str_radix(&modalias[20..28], 16).map_err(econvert)?;

        Ok(Self {
            bus,
            group,
            vid,
            pid,
        })
    }

    pub fn from_static_str(modalias: &'static str) -> std::io::Result<Self> {
        Self::from_str(&modalias)
    }

    pub fn from_udev_device(udev_device: &udev::Device) -> std::io::Result<Self> {
        let modalias = udev_device.property_value("MODALIAS");

        let modalias = match modalias {
            Some(data) => data,
            _ => std::ffi::OsStr::new("hid:empty"), //panic!("modalias is empty"),
        };

        let modalias = match modalias.to_str() {
            Some(data) => data,
            _ => panic!("modalias problem"),
        };

        Self::from_str(modalias)
    }
}
