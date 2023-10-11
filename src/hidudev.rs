// SPDX-License-Identifier: GPL-2.0-only

use crate::bpf;
use crate::modalias::Modalias;
use globset::GlobBuilder;
use log;

pub struct HidUdev {
    udev_device: udev::Device,
}

impl HidUdev {
    pub fn from_syspath(syspath: &std::path::PathBuf) -> std::io::Result<Self> {
        let mut device = udev::Device::from_syspath(syspath.as_path())?;
        let subsystem = device.property_value("SUBSYSTEM");

        let is_hid_device = match subsystem {
            Some(sub) => sub == "hid",
            None => false,
        };

        if !is_hid_device {
            log::debug!(
                "Device {} is not a HID device, searching for parent devices",
                syspath.display()
            );
            if let Some(parent) = device.parent_with_subsystem("hid")? {
                log::debug!("Using {}", parent.syspath().to_str().unwrap());
                device = parent
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Device {} is not a HID device", syspath.display()),
                ));
            }
        };

        Ok(HidUdev {
            udev_device: device,
        })
    }

    pub fn modalias(&self) -> Modalias {
        Modalias::from_udev_device(&self.udev_device).unwrap()
    }

    pub fn sysname(&self) -> String {
        String::from(self.udev_device.sysname().to_str().unwrap())
    }

    pub fn syspath(&self) -> String {
        String::from(self.udev_device.syspath().to_str().unwrap())
    }

    pub fn id(&self) -> u32 {
        let hid_sys = self.sysname();
        u32::from_str_radix(&hid_sys[15..], 16).unwrap()
    }

    pub fn load_bpf_from_directory(&self, bpf_dir: std::path::PathBuf) -> std::io::Result<()> {
        if !bpf_dir.exists() {
            return Ok(());
        }

        let modalias = self.modalias();

        let glob_path = bpf_dir.join(format!(
            "b{{{:04X},\\*}}g{{{:04X},\\*}}v{{{:08X},\\*}}p{{{:08X},\\*}}*.bpf.o",
            modalias.bus, modalias.group, modalias.vid, modalias.pid,
        ));

        let globset = GlobBuilder::new(glob_path.as_path().to_str().unwrap())
            .literal_separator(true)
            .case_insensitive(true)
            .build()
            .unwrap()
            .compile_matcher();

        let mut matches = Vec::new();
        for elem in bpf_dir.read_dir().unwrap() {
            if let Ok(dir_entry) = elem {
                let path = dir_entry.path();
                if globset.is_match(&path.to_str().unwrap()) && path.is_file() {
                    log::debug!(
                        "device added {}, filename: {}",
                        self.sysname(),
                        path.display(),
                    );
                    matches.push(path);
                }
            }
        }

        if !matches.is_empty() {
            let hid_bpf_loader = bpf::HidBPF::new().unwrap();
            for path in matches {
                hid_bpf_loader.load_programs(path, self).unwrap();
            }
        }

        Ok(())
    }

    pub fn remove_bpf_objects(&self) -> std::io::Result<()> {
        log::info!("device removed");

        let path = bpf::get_bpffs_path(&self.sysname());

        std::fs::remove_dir_all(path).ok();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modalias::Bus;

    #[test]
    fn test_modalias() {
        let modalias = "b0003g0001v000004D9p0000A09F";
        let m = Modalias::from_static_str(modalias);
        assert!(m.is_ok());
        let m = m.unwrap();
        assert!(m.bus == Bus::USB);
        assert!(m.group == 0x0001);
        assert!(m.vid == 0x04d9);
        assert!(m.pid == 0xa09f);

        // parsing doesn't care about uppercase hex
        let m = Modalias::from_str(modalias.to_lowercase().as_str());
        assert!(m.is_ok());
        let m = m.unwrap();
        assert!(m.bus == Bus::USB);
        assert!(m.group == 0x0001);
        assert!(m.vid == 0x04d9);
        assert!(m.pid == 0xa09f);

        // 4-digit vid
        let modalias = "b0003g0001v04D9p0000A09F";
        let m = Modalias::from_str(modalias.to_lowercase().as_str());
        assert!(m.is_err());

        // 4-digit pid
        let modalias = "b0003g0001v000004D9pA09F";
        let m = Modalias::from_str(modalias.to_lowercase().as_str());
        assert!(m.is_err());

        // invalid char
        let modalias = "b0003g0001v0000g4D9pA09F";
        let m = Modalias::from_str(modalias.to_lowercase().as_str());
        assert!(m.is_err());
    }
}
