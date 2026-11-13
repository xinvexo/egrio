use super::*;

/// A directory of its own, removed afterwards.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("egrio-geodata-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn put_varint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn put_bytes(number: u64, bytes: &[u8], out: &mut Vec<u8>) {
    put_varint(number << 3 | 2, out);
    put_varint(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

/// A `geoip.dat` with one code and one network.
fn geoip_file(code: &str, network: [u8; 4], prefix: u64) -> Vec<u8> {
    let mut cidr = Vec::new();
    put_bytes(1, &network, &mut cidr);
    put_varint(2 << 3, &mut cidr);
    put_varint(prefix, &mut cidr);
    let mut entry = Vec::new();
    put_bytes(1, code.as_bytes(), &mut entry);
    put_bytes(2, &cidr, &mut entry);
    let mut file = Vec::new();
    put_bytes(1, &entry, &mut file);
    file
}

/// A `geosite.dat` with one code and one domain with its subdomains.
fn geosite_file(code: &str, domain: &str) -> Vec<u8> {
    let mut site = Vec::new();
    put_varint(1 << 3, &mut site);
    put_varint(2, &mut site);
    put_bytes(2, domain.as_bytes(), &mut site);
    let mut entry = Vec::new();
    put_bytes(1, code.as_bytes(), &mut entry);
    put_bytes(2, &site, &mut entry);
    let mut file = Vec::new();
    put_bytes(1, &entry, &mut file);
    file
}

fn codes(geoip: &[&str], geosite: &[&str]) -> GeoDataCodes {
    GeoDataCodes {
        geoip: geoip.iter().map(|code| code.to_string()).collect(),
        geosite: geosite.iter().map(|code| code.to_string()).collect(),
    }
}

#[test]
fn a_stored_file_reports_its_size_and_is_rewritten_only_when_it_changes() {
    let directory = TempDir::new();
    assert!(status_in(directory.path()).geoip.is_none());

    let file = geoip_file("CN", [1, 0, 1, 0], 24);
    GeoDataFile::GeoIp.validate(&file).unwrap();
    assert!(store(directory.path(), GeoDataFile::GeoIp, &file).unwrap());
    assert!(!store(directory.path(), GeoDataFile::GeoIp, &file).unwrap());
    let status = status_in(directory.path());
    assert_eq!(status.geoip.unwrap().size_bytes, file.len() as u64);
    assert!(status.geosite.is_none());
    assert!(
        !directory.path().join("geoip.dat.download").exists(),
        "the partial download was renamed into place"
    );

    let newer = geoip_file("CN", [1, 0, 2, 0], 24);
    assert!(store(directory.path(), GeoDataFile::GeoIp, &newer).unwrap());
    assert_eq!(
        std::fs::read(directory.path().join("geoip.dat")).unwrap(),
        newer
    );
}

#[test]
fn a_download_that_does_not_decode_is_refused() {
    assert!(GeoDataFile::GeoIp
        .validate(b"<html>not found</html>")
        .is_err());
    assert!(GeoDataFile::GeoSite.validate(&[]).is_err());
    assert!(GeoDataFile::GeoSite
        .validate(&geosite_file("CN", "baidu.com"))
        .is_ok());
}

#[test]
fn only_the_named_codes_of_the_files_on_disk_reach_the_profile() {
    let directory = TempDir::new();
    let wanted = codes(&["CN"], &["cn"]);
    assert_eq!(
        content_in(directory.path(), &wanted),
        GeoDataContent::default(),
        "missing files leave the rules waiting"
    );

    store(
        directory.path(),
        GeoDataFile::GeoIp,
        &geoip_file("CN", [1, 0, 1, 0], 24),
    )
    .unwrap();
    std::fs::write(directory.path().join("geosite.dat"), b"corrupt").unwrap();
    let content = content_in(directory.path(), &wanted);
    assert_eq!(
        content.geoip.unwrap()[0].cidrs.iter().collect::<Vec<_>>(),
        ["1.0.1.0/24"]
    );
    assert_eq!(
        content.geosite, None,
        "an unreadable file counts as missing"
    );

    store(
        directory.path(),
        GeoDataFile::GeoSite,
        &geosite_file("CN", "baidu.com"),
    )
    .unwrap();
    let content = content_in(directory.path(), &codes(&[], &["cn"]));
    assert_eq!(content.geoip, None, "a kind no rule names is not read");
    assert_eq!(
        content.geosite.unwrap()[0].names.iter().collect::<Vec<_>>(),
        ["+.baidu.com"]
    );
}

#[test]
fn sources_name_the_mirror_before_the_release() {
    let [mirror, release] = GeoDataFile::GeoSite.sources();
    assert_eq!(
        mirror,
        "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat"
    );
    assert!(release.starts_with("https://github.com/Loyalsoldier/v2ray-rules-dat/releases/"));
}
