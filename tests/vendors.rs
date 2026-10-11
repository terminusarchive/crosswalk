use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use crosswalk::vendors::Vendors;

const TABLE: &str = "OUI/MA-L                                                    Organization\n\
company_id                                                  Organization\n\
                                                            Address\n\
\n\
28-6F-B9   (hex)\t\tNokia Shanghai Bell Co., Ltd.\n\
286FB9     (base 16)\t\tNokia Shanghai Bell Co., Ltd.\n\
\t\t\t\tNo.388 Ning Qiao Road,Jin Qiao Pudong Shanghai\n\
\t\t\t\tCN\n\
\n\
E8-0A-B9   (hex)\t\tCisco Systems, Inc\n\
E80AB9     (base 16)\t\tCisco Systems, Inc\n\
\n\
02-00-5E   (hex)\t\tHeld Under A Local Bit\n";

fn file(name: &str, contents: &[u8]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("crosswalk-vendors-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = dir.join(format!("{}-{name}", NEXT.fetch_add(1, Ordering::Relaxed)));
    std::fs::write(&path, contents).unwrap();
    path
}

fn table() -> Vendors {
    Vendors::load(file("oui.txt", TABLE.as_bytes()))
}

#[test]
fn a_known_prefix_gives_its_vendor_in_lower_and_upper_case() {
    let vendors = table();
    assert_eq!(
        vendors.maker("28:6f:b9:01:02:03"),
        Some("Nokia Shanghai Bell Co., Ltd.")
    );
    assert_eq!(
        vendors.maker("28:6F:B9:01:02:03"),
        Some("Nokia Shanghai Bell Co., Ltd.")
    );
    assert_eq!(
        vendors.maker("e8:0a:b9:ff:ff:ff"),
        Some("Cisco Systems, Inc")
    );
}

#[test]
fn an_unknown_prefix_gives_nothing() {
    assert_eq!(table().maker("a4:00:00:00:00:cd"), None);
}

#[test]
fn a_locally_administered_address_is_private_whatever_the_table_holds() {
    let vendors = table();
    assert_eq!(vendors.maker("02:00:5e:00:00:01"), Some("private"));
    assert_eq!(vendors.maker("aa:bb:cc:dd:ee:ff"), Some("private"));
    assert_eq!(
        Vendors::default().maker("06:11:22:33:44:55"),
        Some("private")
    );
}

#[test]
fn a_missing_empty_or_garbage_file_is_an_empty_table() {
    let missing = Vendors::load(std::env::temp_dir().join("crosswalk-vendors-no-such-file"));
    let empty = Vendors::load(file("empty.txt", b""));
    let garbage = Vendors::load(file(
        "garbage.txt",
        b"\xff\xfe\x00 (hex) \n(hex)\nZZ-ZZ-ZZ   (hex)\t\tNobody\n28-6F   (hex)\t\tShort\n28-6F-B9   (hex)\n\x00\x01\x02\n",
    ));
    for vendors in [missing, empty, garbage] {
        assert_eq!(vendors.len(), 0);
        assert_eq!(vendors.maker("28:6f:b9:01:02:03"), None);
    }
}

#[test]
fn an_unreadable_hardware_address_has_no_maker() {
    let vendors = table();
    assert_eq!(vendors.maker(""), None);
    assert_eq!(vendors.maker("28:6f"), None);
    assert_eq!(vendors.maker("zz:6f:b9:01:02:03"), None);
}

#[test]
fn an_all_zero_hardware_address_has_no_maker_though_the_prefix_is_listed() {
    let vendors = Vendors::load(file(
        "xerox.txt",
        b"00-00-00   (hex)\t\tXEROX CORPORATION\n",
    ));
    assert_eq!(vendors.maker("00:00:00:00:00:00"), None);
    assert_eq!(
        vendors.maker("00:00:00:01:02:03"),
        Some("XEROX CORPORATION")
    );
}
