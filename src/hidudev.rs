// SPDX-License-Identifier: GPL-2.0-only

use crate::bpf;
use crate::modalias::Modalias;
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

    /// Find the given file name in the set of directories, returning a path
    /// to the first filename found. The directories are assumed in preference
    /// order, first match wins.
    fn find_file(dirs: &[std::path::PathBuf], filename: &str) -> Option<std::path::PathBuf> {
        dirs.iter()
            .map(|d| d.join(filename))
            .find(|path| path.is_file())
    }

    pub fn load_bpf_from_directories(
        &self,
        bpf_dirs: &[std::path::PathBuf],
        prog: Option<String>,
    ) -> std::io::Result<()> {
        if !bpf_dirs.iter().any(|d| d.exists()) {
            return Ok(());
        }

        let mut paths = Vec::new();

        if prog.is_none() {
            for property in self.udev_device.properties() {
                let property_name = property.name().to_str().unwrap();

                log::debug!("property: {:?} = {:?}", property_name, property.value());

                if property_name == "HID_BPF_IGNORE_DEVICE" {
                    return Ok(());
                }
                if property_name.starts_with("HID_BPF_") {
                    let value = property.value().to_str().unwrap();
                    if let Some(target_object) = HidUdev::find_file(bpf_dirs, value) {
                        log::debug!(
                            "device added {}, filename: {}",
                            self.sysname(),
                            target_object.display(),
                        );
                        paths.push(target_object);
                    }
                }
            }
        } else if let Some(target_object) = HidUdev::find_file(bpf_dirs, &prog.unwrap()) {
            log::debug!(
                "device added {}, filename: {}",
                self.sysname(),
                target_object.display(),
            );
            paths.push(target_object);
        }

        if !paths.is_empty() {
            let hid_bpf_loader = bpf::HidBPF::new().unwrap();
            for path in paths {
                if let Err(e) = hid_bpf_loader.load_programs(&path, self) {
                    log::warn!("Failed to load {:?}: {:?}", path, e);
                };
            }
        }

        Ok(())
    }

    pub fn remove_bpf_objects(&self) -> std::io::Result<()> {
        log::info!("device removed");

        let path = bpf::get_bpffs_path(&self.sysname(), "");

        std::fs::remove_dir_all(path).ok();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modalias::{Bus, Group};

    #[test]
    fn test_modalias() {
        let modalias = "b0003g0001v000004D9p0000A09F";
        let m = Modalias::from_static_str(modalias);
        assert!(m.is_ok());
        let m = m.unwrap();
        assert!(m.bus == Bus::USB);
        assert!(m.group == Group::Generic);
        assert!(m.vid == 0x04d9);
        assert!(m.pid == 0xa09f);

        // parsing doesn't care about uppercase hex
        let m = Modalias::from_str(modalias.to_lowercase().as_str());
        assert!(m.is_ok());
        let m = m.unwrap();
        assert!(m.bus == Bus::USB);
        assert!(m.group == Group::Generic);
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
