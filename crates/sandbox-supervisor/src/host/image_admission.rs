//! The public image identifier must name the bytes the guardian will stage.
use super::Image;
use anyhow::{Result, ensure};
use std::collections::BTreeMap;

pub(super) fn validate(images: &BTreeMap<String, Image>) -> Result<()> {
    for (digest, image) in images {
        ensure!(
            sandbox_protocol::images::valid_image_digest(digest)
                && digest == &format!("sha256:{}", image.rootfs.sha256),
            "configured image identifier does not match rootfs artifact digest"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guardian::Artifact;

    #[test]
    fn an_allowlisted_identifier_cannot_alias_a_different_rootfs() {
        let image = Image {
            kernel: Artifact {
                path: "/never-open/kernel".into(),
                sha256: "c".repeat(64),
            },
            rootfs: Artifact {
                path: "/never-open/rootfs".into(),
                sha256: "a".repeat(64),
            },
        };
        let authorized = format!("sha256:{}", "a".repeat(64));
        let other = format!("sha256:{}", "b".repeat(64));
        assert!(validate(&BTreeMap::from([(authorized.clone(), image.clone())])).is_ok());
        assert!(validate(&BTreeMap::from([(other.clone(), image.clone())])).is_err());
        assert!(
            validate(&BTreeMap::from([
                (authorized, image.clone()),
                (other, image.clone())
            ]))
            .is_err()
        );
        for invalid in ["latest".into(), format!("SHA256:{}", "a".repeat(64))] {
            assert!(validate(&BTreeMap::from([(invalid, image.clone())])).is_err());
        }
    }
}
