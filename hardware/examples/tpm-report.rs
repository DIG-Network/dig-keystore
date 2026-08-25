//! Report what this host actually resolves to. Prints no key material.
fn main() {
    for c in dig_keystore_hardware::platform_candidates() {
        println!("kind    = {}", c.kind());
        println!("probe   = {:?}", c.probe());
        println!("custody = {:?}", c.custody());
    }
    let r = dig_keystore_hardware::ladder::walk(
        &dig_keystore_hardware::platform_candidates(),
        dig_keystore::hardware::HardwarePolicy::Optional,
    );
    println!("rung    = {:?}", r.map(|x| x.tier().to_string()));
}
