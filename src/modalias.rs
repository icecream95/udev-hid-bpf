use libbpf_rs::btf::types as BtfTypes;
use libbpf_rs::ReferencesType;
use log;

#[derive(Debug, PartialEq, Hash, Eq)]
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

impl From<Bus> for String {
    fn from(bus: Bus) -> String {
        match bus {
            Bus::Any => String::from("*"),
            _ => format!("{:04X}", bus),
        }
    }
}

#[derive(Debug, PartialEq, Hash, Eq)]
pub enum Group {
    Any,
    Generic,
    Multitouch,
    SensorHub,
    MultitouchWin8,
    RMI,
    Wacom,
    LogitechDJ,
    Steam,
    Logitech27mhz,
    Vivaldi,
}

impl TryFrom<usize> for Group {
    type Error = &'static str;

    fn try_from(sz: usize) -> Result<Self, Self::Error> {
        match sz {
            0x00 => Ok(Group::Any),
            0x01 => Ok(Group::Generic),
            0x02 => Ok(Group::Multitouch),
            0x03 => Ok(Group::SensorHub),
            0x04 => Ok(Group::MultitouchWin8),
            0x0100 => Ok(Group::RMI),
            0x0101 => Ok(Group::Wacom),
            0x0102 => Ok(Group::LogitechDJ),
            0x0103 => Ok(Group::Steam),
            0x0104 => Ok(Group::Logitech27mhz),
            0x0105 => Ok(Group::Vivaldi),
            _ => Err("Invalid group type"),
        }
    }
}

impl From<&Group> for usize {
    fn from(group: &Group) -> Self {
        match group {
            Group::Any => 0x00,
            Group::Generic => 0x01,
            Group::Multitouch => 0x02,
            Group::SensorHub => 0x03,
            Group::MultitouchWin8 => 0x04,
            Group::RMI => 0x0100,
            Group::Wacom => 0x0101,
            Group::LogitechDJ => 0x0102,
            Group::Steam => 0x0103,
            Group::Logitech27mhz => 0x0104,
            Group::Vivaldi => 0x0105,
        }
    }
}

impl From<Group> for String {
    fn from(group: Group) -> String {
        match group {
            Group::Any => String::from("*"),
            _ => format!("{:04X}", group),
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

impl std::fmt::UpperHex for Group {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val: usize = self.into();
        std::fmt::UpperHex::fmt(&val, f)
    }
}

impl std::fmt::LowerHex for Group {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val: usize = self.into();
        std::fmt::LowerHex::fmt(&val, f)
    }
}

pub struct Metadata<'m> {
    btf: &'m libbpf_rs::btf::Btf<'m>,
    types: BtfTypes::Union<'m>,
}

impl<'m> Metadata<'m> {
    pub fn from_btf<'a>(btf: &'a libbpf_rs::btf::Btf<'m>) -> Option<Self>
    where
        'a: 'm,
    {
        let datasec = btf.type_by_name::<libbpf_rs::btf::types::DataSec>(".hid_bpf_config")?;

        for var_sec_info in datasec.iter() {
            log::debug!(target:"HID-BPF metadata", "{:?}", var_sec_info);

            let var = btf.type_by_id::<BtfTypes::Var>(var_sec_info.ty)?;

            let var_type = var.referenced_type().skip_mods_and_typedefs();

            log::debug!(target:"HID-BPF metadata", "  -> {:?} / {:?}", var, var_type);

            if let Ok(hb_union) = BtfTypes::Union::try_from(var_type) {
                return Some(Metadata {
                    btf,
                    types: hb_union,
                });
            }
        }

        None
    }

    pub fn modaliases(&self) -> impl Iterator<Item = Modalias> + '_ {
        /* parse the HID_BPF config section */
        self.types
            .iter()
            .enumerate()
            .filter_map(|(_, e)| Modalias::from_btf_type_id(&self.btf, e))
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
pub struct Modalias {
    pub bus: Bus,
    pub group: Group,
    pub vid: u32,
    pub pid: u32,
}

impl Modalias {
    fn new() -> Modalias {
        Modalias {
            bus: Bus::Any,
            group: Group::Any,
            vid: 0,
            pid: 0,
        }
    }

    fn from_btf_type_id(
        btf: &libbpf_rs::btf::Btf,
        union_member: BtfTypes::UnionMember,
    ) -> Option<Modalias> {
        let device_descr = btf.type_by_id::<BtfTypes::Struct>(union_member.ty)?;

        let mut prefix = String::from("");

        let mut modalias = Modalias::new();

        for member in device_descr.iter() {
            let member_name = String::from(member.name.unwrap().to_str().unwrap());
            log::debug!(target:"HID-BPF metadata", "    -> {:?}", member);
            if let Some(Ok(array)) = btf
                .type_by_id::<BtfTypes::Ptr>(member.ty)
                .map(|pointer| BtfTypes::Array::try_from(pointer.referenced_type()))
            {
                // if prefix is not set, we are at the first element
                if prefix == "" {
                    prefix = member_name + "_";
                    continue;
                }

                if let Some(name) = member_name.strip_prefix(&prefix) {
                    match name {
                        "bus" => modalias.bus = Bus::try_from(array.capacity()).unwrap(),
                        "group" => modalias.group = Group::try_from(array.capacity()).unwrap(),
                        "vid" => modalias.vid = u32::try_from(array.capacity()).unwrap(),
                        "pid" => modalias.pid = u32::try_from(array.capacity()).unwrap(),
                        _ => (),
                    }
                    log::debug!(target:"HID-BPF metadata", "      -> {:?}: {:#06X}", name, array.capacity());
                }
            }
        }
        Some(modalias)
    }

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
        let group = Group::try_from(usize::from_str_radix(&modalias[6..10], 16).map_err(econvert)?)
            .unwrap();
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

impl From<Modalias> for String {
    fn from(modalias: Modalias) -> String {
        let vid = match modalias.vid {
            0 => String::from("*"),
            _ => format!("{:08X}", modalias.vid),
        };
        let pid = match modalias.pid {
            0 => String::from("*"),
            _ => format!("{:08X}", modalias.pid),
        };

        format!(
            "b{}g{}v{}p{}",
            String::from(modalias.bus),
            String::from(modalias.group),
            vid,
            pid
        )
    }
}
