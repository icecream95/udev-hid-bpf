// SPDX-License-Identifier: GPL-2.0-only

use crate::bpf;
use crate::modalias::Modalias;
use log;
use std::str::FromStr;

pub struct HidUdev {
    udev_device: udev::Device,
}

impl HidUdev {
    pub fn from_syspath(syspath: &std::path::Path) -> std::io::Result<Self> {
        let mut device = udev::Device::from_syspath(syspath)?;
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
        let data = self
            .udev_device
            .property_value("MODALIAS")
            .unwrap_or(std::ffi::OsStr::new("hid:empty"));
        let data = data.to_str().expect("modalias problem");
        Modalias::from_str(data).unwrap()
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

    pub fn hid_bpf_properties(&self) -> Vec<String> {
        self.udev_device
            .properties()
            .map(|prop| {
                let name = String::from(prop.name().to_str().unwrap_or_default());
                let value = String::from(prop.value().to_str().unwrap_or_default());
                (name, value)
            })
            .filter(|(name, _)| name.starts_with("HID_BPF_"))
            .map(|(_, value)| value)
            .collect()
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

        if let Some(prog) = prog {
            let target_path = std::path::PathBuf::from(&prog);
            let target_object = if target_path.exists() {
                Some(target_path)
            } else {
                HidUdev::find_file(bpf_dirs, &prog)
            };

            if let Some(target_object) = target_object {
                log::debug!(
                    "device added {}, filename: {}",
                    self.sysname(),
                    target_object.display(),
                );
                paths.push(target_object);
            }
        } else {
            if self
                .udev_device
                .property_value("HID_BPF_IGNORE_DEVICE")
                .is_some()
            {
                return Ok(());
            }
            for property in self.hid_bpf_properties() {
                if let Some(target_object) = HidUdev::find_file(bpf_dirs, &property) {
                    log::debug!(
                        "device added {}, filename: {}",
                        self.sysname(),
                        target_object.display(),
                    );
                    paths.push(target_object);
                }
            }
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
