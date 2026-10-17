//! Exercise the public contracts affected by the vendored dependency fixes.
#![cfg(test)]

#[cfg(target_os = "linux")]
use glib::variant::ToVariant;

#[cfg(target_os = "linux")]
#[test]
fn string_variant_iterators_preserve_borrowed_utf8_in_both_directions() {
    let values = ["retained", "", "á", "日本語", "last"];
    let variant = values.to_variant();
    let mut iter = variant.array_iter_str().unwrap();
    let first = iter.next().unwrap();
    assert_eq!(first, values[0]);
    assert_eq!(iter.next_back(), Some(values[4]));
    assert_eq!(iter.nth(1), Some(values[2]));
    assert_eq!(iter.last(), Some(values[3]));
    assert_eq!(first, values[0]);
    assert_eq!(
        variant.array_iter_str().unwrap().rev().collect::<Vec<_>>(),
        values.into_iter().rev().collect::<Vec<_>>()
    );
    assert_eq!(
        variant.array_iter_str().unwrap().nth_back(2),
        Some(values[2])
    );
    assert!(Vec::<String>::new()
        .to_variant()
        .array_iter_str()
        .unwrap()
        .next()
        .is_none());
}

#[test]
fn generated_perfect_hash_tables_resolve_every_original_key() {
    for count in [1, 7, 63, 500] {
        let keys = (0..count)
            .map(|i| format!("attribute-{i}-á"))
            .collect::<Vec<_>>();
        let table = phf_generator::generate_hash(&keys);
        assert_eq!(table.map.len(), keys.len());
        for key in &keys {
            let hash = phf_shared::hash(key, &table.key);
            let (d1, d2) = table.disps[hash.g as usize % table.disps.len()];
            let index = phf_shared::displace(hash.f1, hash.f2, d1, d2) as usize % table.map.len();
            assert_eq!(&keys[table.map[index]], key);
        }
    }
}
