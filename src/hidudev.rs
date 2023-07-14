// SPDX-License-Identifier: GPL-2.0-only

use crate::bpf;
use globset::GlobBuilder;
use log;

pub struct HidUdev {
    udev_device: udev::Device,
}

impl HidUdev {
    pub fn from_syspath(syspath: std::path::PathBuf) -> std::io::Result<Self> {
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

    pub fn modalias(&self) -> String {
        let modalias = self.udev_device.property_value("MODALIAS");

        let modalias = match modalias {
            Some(data) => data,
            _ => std::ffi::OsStr::new("hid:empty"), //panic!("modalias is empty"),
        };

        let modalias = match modalias.to_str() {
            Some(data) => data,
            _ => panic!("modalias problem"),
        };

        /* strip out the "hid:" prefix from the modalias */
        String::from(modalias)
            .trim_start_matches("hid:")
            .replace("v0000", "v")
            .replace("p0000", "p")
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

        let prefix = self.modalias();

        if prefix.len() != 20 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid modalias {} for device {}", prefix, self.sysname()),
            ));
        }

        let glob_path = bpf_dir.join(format!(
            "b{{{},\\*}}g{{{},\\*}}v{{{},\\*}}p{{{},\\*}}*.bpf.o",
            &prefix[1..5],
            &prefix[6..10],
            &prefix[11..15],
            &prefix[16..20],
        ));

        log::debug!(
            "device added {}, filename: {}",
            self.sysname(),
            glob_path.as_path().display()
        );

        let globset = GlobBuilder::new(glob_path.as_path().to_str().unwrap())
            .literal_separator(true)
            .case_insensitive(true)
            .build()
            .unwrap()
            .compile_matcher();

        let mut hid_bpf_loader = bpf::HidBPF::new();

        for elem in bpf_dir.read_dir().unwrap() {
            if let Ok(dir_entry) = elem {
                let path = dir_entry.path();
                if globset.is_match(&path.to_str().unwrap()) && path.is_file() {
                    hid_bpf_loader.open_and_load().unwrap();
                    hid_bpf_loader.load_programs(path, self).unwrap();
                }
            }
        }

        Ok(())
    }

    pub fn remove_bpf_objects(&self) -> std::io::Result<()> {
        log::info!("device removed");

        let path = bpf::get_bpffs_path(self);

        std::fs::remove_dir_all(path).ok();

        Ok(())
    }
}
