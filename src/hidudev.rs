// SPDX-License-Identifier: GPL-2.0-only

use crate::bpf;
use crate::modalias::Modalias;
use log;
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;

pub struct HidUdev {
    udev_device: udev::Device,
}

#[derive(Debug, Clone)]
pub struct HidUdevProperty {
    pub name: String,
    pub value: String,
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

    pub fn udev_properties(&self) -> Vec<HidUdevProperty> {
        self.udev_device
            .properties()
            .flat_map(|prop| -> Option<HidUdevProperty> {
                let name = String::from(prop.name().to_str()?);
                let value = String::from(prop.value().to_str()?);
                Some(HidUdevProperty { name, value })
            })
            .collect()
    }

    pub fn is_ignored(&self) -> bool {
        self.udev_device
            .property_value("HID_BPF_IGNORE_DEVICE")
            .is_some()
    }

    /// Find the given file name in the set of directories, returning a path
    /// to the first filename found. The directories are assumed in preference
    /// order, first match wins.
    fn find_first_matching_file(dirs: &[PathBuf], filename: &str) -> Option<PathBuf> {
        dirs.iter()
            .map(|d| d.join(filename))
            .find(|path| path.is_file())
    }

    /// Given a set of paths that have filenames prefixed like 0010-foo.bpf.o, 0020-bar.bpf.o,
    /// return a set of priority-ordered filenames, i.e.
    /// [
    ///   ["0020-bar.bpf.o", "0010-bar.bpf.o"],
    ///   ["0010-foo.bpf.o"]
    /// ]
    /// We can then iterate through and load whichever program is happy first.
    fn sort_by_stem(paths: &[PathBuf]) -> Vec<Vec<PathBuf>> {
        let mut ht: HashMap<String, Vec<PathBuf>> = HashMap::new();

        for path in paths.iter() {
            let filename = String::from(path.file_name().unwrap().to_string_lossy());
            let stem = match filename.split_once('-') {
                Some((_, rest)) => String::from(rest).to_lowercase(),
                None => String::from(&filename).to_lowercase(),
            };
            match ht.get_mut(&stem) {
                Some(v) => v.push(PathBuf::from(path)),
                None => {
                    let v = vec![PathBuf::from(path)];
                    ht.insert(stem, v);
                }
            };
        }

        // The list of values is reverse-dict sorted, so 30-foo comes first before 20-foo
        for v in ht.values_mut() {
            v.sort_by(|p1, p2| {
                let p1: String = p1.file_name().unwrap().to_string_lossy().into();
                let p2: String = p2.file_name().unwrap().to_string_lossy().into();

                let p1 = p1.to_lowercase();
                let p2 = p2.to_lowercase();

                p2.cmp(&p1)
            });
        }

        // HashMap's order is unpredictable, to test this let's
        // do a more predictable generation of values: dict sort by stem
        let mut keys: Vec<String> = ht.keys().cloned().collect();
        keys.sort();
        keys.iter().map(|k| ht.remove(k).unwrap()).collect()
    }

    /// For each file find the first matching .bpf.o file within the set of directories.
    pub fn find_named_objfiles(filenames: &[String], bpf_dirs: &[PathBuf]) -> Vec<PathBuf> {
        filenames
            .iter()
            .filter(|filename| filename.ends_with(".bpf.o"))
            .flat_map(|filename| {
                let p = PathBuf::from(filename);
                if p.exists() {
                    Some(p)
                } else {
                    Self::find_first_matching_file(bpf_dirs, filename)
                }
            })
            .collect()
    }

    /// Search for any file in the HID_BPF_ udev properties set on this device
    pub fn search_for_matching_objfiles(&self, bpf_dirs: &[PathBuf]) -> Vec<PathBuf> {
        let paths: Vec<String> = self
            .hid_bpf_properties()
            .iter()
            .flat_map(|p| HidUdev::find_first_matching_file(bpf_dirs, p))
            .inspect(|target_object| {
                log::debug!(
                    "device added {}, filename: {}",
                    self.sysname(),
                    target_object.display()
                )
            })
            .map(|p| String::from(p.to_string_lossy()))
            .collect();

        Self::find_named_objfiles(&paths, bpf_dirs)
    }

    pub fn load_bpf_files(
        &self,
        paths: &[PathBuf],
        properties: &[HidUdevProperty],
    ) -> std::io::Result<()> {
        let sorted: Vec<Vec<PathBuf>> = Self::sort_by_stem(&paths);
        // For each group in our vec of vecs, try to load them one-by-one.
        // The first successful one terminates that group and we continue with the next.
        for group in sorted {
            for path in group {
                match bpf::HidBPF::load_programs(&path, self, properties) {
                    Ok(_) => {
                        log::info!("Successfully loaded {path:?}");
                        break;
                    }
                    Err(e) => log::warn!("Failed to load {:?}: {:?}", path, e),
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

impl From<&HidUdevProperty> for HidUdevProperty {
    fn from(p: &HidUdevProperty) -> HidUdevProperty {
        HidUdevProperty {
            name: p.name.clone(),
            value: p.value.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    #[test]
    fn test_bpf_lookup() {
        let tmpdir = tempfile::tempdir().unwrap();
        let base_path = &tmpdir.path();
        let usr_local = base_path.join("usr/local/lib/firmware");
        let usr = base_path.join("lib/firmware");
        std::fs::create_dir_all(&usr_local).unwrap();
        std::fs::create_dir_all(&usr).unwrap();

        let ignored1 = &usr_local.join("0010-ignored.bpf.c"); // .c extension
        let ignored2 = &usr_local.join("0010-ignored.o"); // not bpf.o
        let p1 = &usr_local.join("0010-one.bpf.o");
        let p2 = &usr.join("0020-one.bpf.o");
        let p3 = &usr_local.join("0010-two.bpf.o");
        let p4 = &usr_local.join("0020-three.bpf.o");
        let p5 = &usr.join("0010-three.bpf.o");
        let _ = &[ignored1, ignored2, p1, p2, p3, p4, p5]
            .iter()
            .for_each(|p| {
                File::create(p).unwrap();
            });

        let dirs = [usr_local.clone(), usr.clone()];

        let props: Vec<String> = ["0010-one.bpf.o", "0020-one.bpf.o", "0010-two.bpf.o"]
            .iter()
            .map(|&s| s.into())
            .collect();
        let objfiles = HidUdev::find_named_objfiles(&props, &dirs);
        assert!(!objfiles.is_empty());
        let expected = [
            &usr_local.join("0010-one.bpf.o"),
            &usr.join("0020-one.bpf.o"),
            &usr_local.join("0010-two.bpf.o"),
        ];
        objfiles
            .iter()
            .zip(expected)
            .for_each(|(objfile, exp)| assert!(&objfile == &exp, "{objfile:?} == {exp:?}"));

        // test that ignored is ignored
        let props: Vec<String> = ["0010-one.bpf.o", "0010-ignored.bpf.c", "0010-two.bpf.o"]
            .iter()
            .map(|&s| s.into())
            .collect();
        let objfiles = HidUdev::find_named_objfiles(&props, &dirs);
        assert!(!objfiles.is_empty());
        let expected = [
            &usr_local.join("0010-one.bpf.o"),
            &usr_local.join("0010-two.bpf.o"),
        ];
        objfiles
            .iter()
            .zip(expected)
            .for_each(|(objfile, exp)| assert!(&objfile == &exp, "{objfile:?} == {exp:?}"));

        // and a non-existing one
        let props: Vec<String> = [
            "0010-one.bpf.o",
            "0010-does-not-exist.bpf.o",
            "0010-three.bpf.o",
        ]
        .iter()
        .map(|&s| s.into())
        .collect();
        let objfiles = HidUdev::find_named_objfiles(&props, &dirs);
        assert!(!objfiles.is_empty());
        let expected = [
            &usr_local.join("0010-one.bpf.o"),
            &usr.join("0010-three.bpf.o"),
        ];
        objfiles
            .iter()
            .filter(|p| p.to_string_lossy().ends_with("bpf.o"))
            .zip(expected)
            .for_each(|(objfile, exp)| assert!(&objfile == &exp, "{objfile:?} == {exp:?}"));
    }

    #[test]
    fn test_bpf_stem_sorting() {
        let tmpdir = tempfile::tempdir().unwrap();
        let base_path = &tmpdir.path();
        let usr_local = base_path.join("usr/local/lib/firmware");
        let usr = base_path.join("lib/firmware");
        std::fs::create_dir_all(&usr_local).unwrap();
        std::fs::create_dir_all(&usr).unwrap();

        let files = vec![
            usr_local.join("0010-one.bpf.o"),
            usr.join("0020-ONE.bpf.o"),
            usr_local.join("0010-two.bpf.o"),
            usr.join("0010-three.bpf.o"),
            usr_local.join("0020-three.bpf.o"),
            usr_local.join("0030-THREE.bpf.o"),
        ];
        let _ = files.iter().for_each(|p| {
            File::create(p).unwrap();
        });

        // The returned list is dict sorted by stem
        let expected: Vec<Vec<PathBuf>> = vec![
            vec![usr.join("0020-ONE.bpf.o"), usr_local.join("0010-one.bpf.o")],
            vec![
                usr_local.join("0030-THREE.bpf.o"),
                usr_local.join("0020-three.bpf.o"),
                usr.join("0010-three.bpf.o"),
            ],
            vec![usr_local.join("0010-two.bpf.o")],
        ];
        let stem_sorted = HidUdev::sort_by_stem(&files);

        for (exp, sorted) in expected.iter().zip(stem_sorted) {
            for (e, s) in exp.iter().zip(sorted) {
                assert!(e == &s, "expected {e:?} == have {s:?}");
            }
        }
    }
}
