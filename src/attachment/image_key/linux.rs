use anyhow::{bail, Result};

use super::{ImageKeyMaterial, ImageKeyProvider};

pub struct LinuxImageKeyProvider;

impl ImageKeyProvider for LinuxImageKeyProvider {
    fn get_key(&self, _wxid: &str) -> Result<ImageKeyMaterial> {
        bail!("Linux V2 image key is not implemented yet; use legacy/V1 images for now")
    }
}
