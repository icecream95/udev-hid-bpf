#[derive(Debug)]
pub struct Modalias {
    pub bus: u32,
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

        let bus = u32::from_str_radix(&modalias[1..5], 16).map_err(econvert)?;
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
