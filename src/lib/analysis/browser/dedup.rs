use crate::volatility::Record;
use serde_json::json;
use std::collections::BTreeMap;

/// Collapse memory query prefixes, keeping provenance for every URL variant.
pub(super) fn memory_searches(rows: &mut Vec<Record>) {
    let mut searches = BTreeMap::<_, BTreeMap<String, Vec<usize>>>::new();
    for (index, row) in rows.iter().enumerate() {
        let terms = row.text("Search terms");
        if row.text("Kind") != "Memory search" || terms.is_empty() {
            continue;
        }
        let Ok(url) = url::Url::parse(&row.text("URL")) else {
            continue;
        };
        let scope = [
            row.text("PID"),
            row.text("Source file"),
            row.text("Search engine"),
            row.text("Query origin"),
            url.origin().ascii_serialization(),
            url.path().to_owned(),
        ];
        searches
            .entry(scope)
            .or_default()
            .entry(terms)
            .or_default()
            .push(index);
    }

    let mut removed = vec![false; rows.len()];
    for terms in searches.into_values() {
        let mut groups: Vec<(String, Vec<usize>)> = Vec::new();
        // Reverse lexical order puts extensions before their prefixes. Separate
        // branches survive; a shared prefix joins the first lexical extension.
        for (term, indices) in terms.into_iter().rev() {
            if let Some((longest, group)) = groups.last_mut()
                && longest.starts_with(&term)
            {
                group.extend(indices);
            } else {
                groups.push((term, indices));
            }
        }
        for (_, group) in groups.into_iter().filter(|(_, group)| group.len() > 1) {
            let representative = group[0];
            let mut occurrences = 0u64;
            let variants: Vec<_> = group
                .into_iter()
                .map(|index| {
                    removed[index] = index != representative;
                    let row = &rows[index];
                    occurrences += row
                        .fields
                        .get("Occurrences")
                        .and_then(|value| value.as_u64())
                        .unwrap_or(0);
                    [
                        "URL",
                        "Search terms",
                        "Virtual address",
                        "Dump offset",
                        "Encoding",
                        "Occurrences",
                        "String boundary",
                    ]
                    .into_iter()
                    .filter_map(|key| row.fields.get(key).map(|value| (key, value.clone())))
                    .collect::<BTreeMap<_, _>>()
                })
                .collect();
            rows[representative]
                .fields
                .insert("Grouped occurrences".into(), json!(occurrences));
            rows[representative]
                .fields
                .insert("Search variants".into(), json!(variants));
        }
    }
    let mut index = 0;
    rows.retain(|_| {
        let keep = !removed[index];
        index += 1;
        keep
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{browser::search, record};

    fn query(address: &str, offset: u64) -> Record {
        let (engine, terms) = search::search_terms(address).unwrap();
        let url = url::Url::parse(address).unwrap();
        record(json!({
            "Kind": "Memory search", "PID": 42, "Source file": "analyses/run/pid.42.dmp",
            "Search engine": engine, "Search terms": terms,
            "Query origin": search::query_origin(&url), "URL": address,
            "Virtual address": format!("{:#x}", 4096 + offset), "Dump offset": offset,
            "Encoding": "UTF-8", "Occurrences": 2,
            "String boundary": "Delimiter found; adjacent text may be included"
        }))
    }

    #[test]
    fn annotation_prefixes_and_tracking_variants_keep_the_full_query_and_provenance() {
        let mut rows: Vec<_> = [
            "https://www.bing.com/search?q=https%3A%2F%2Fwww.searc&FORM=ANNTA1&cvid=1",
            "https://www.bing.com/search?q=https%3A%2F%2Fwww.search.com&FORM=ANNTA1&cvid=2",
            "https://www.bing.com/search?q=https://www.search.com&FORM=ANNTA1&cvid=3",
            "https://www.bing.com/search?q=https%3A%2F%2Fwww.search.co&FORM=ANNTA1&cvid=4",
        ]
        .into_iter()
        .enumerate()
        .map(|(index, url)| query(url, index as u64 * 100))
        .collect();
        let original = rows[1].clone();
        memory_searches(&mut rows);
        assert_eq!(rows.len(), 1);
        for key in [
            "URL",
            "Search terms",
            "Virtual address",
            "Dump offset",
            "Occurrences",
        ] {
            assert_eq!(rows[0].fields[key], original.fields[key]);
        }
        assert_eq!(rows[0].fields["Grouped occurrences"], 8);
        let variants = rows[0].fields["Search variants"].as_array().unwrap();
        assert_eq!(variants.len(), 4);
        for offset in [0, 100, 200, 300] {
            assert!(variants.iter().any(|v| v["Dump offset"] == offset));
        }
        let grouped = rows[0].fields.clone();
        memory_searches(&mut rows);
        assert_eq!(rows[0].fields, grouped);
    }

    #[test]
    fn distinct_extensions_case_and_non_prefix_substrings_survive() {
        let mut rows: Vec<_> = [
            "caf%C3%A9",
            "caf%C3%A9+tea",
            "caf%C3%A9+tea+recipe",
            "caf%C3%A9+coffee",
            "tea",
            "Caf%C3%A9",
            "iced+caf%C3%A9+tea",
        ]
        .into_iter()
        .map(|term| query(&format!("https://www.bing.com/search?q={term}"), 0))
        .collect();
        memory_searches(&mut rows);
        let terms: Vec<_> = rows.iter().map(|r| r.text("Search terms")).collect();
        assert_eq!(
            terms,
            [
                "café tea recipe",
                "café coffee",
                "tea",
                "Café",
                "iced café tea"
            ]
        );
    }

    #[test]
    fn grouping_respects_process_source_endpoint_origin_and_record_kind() {
        let base = query("https://www.bing.com/search?q=tea", 0);
        let mut rows = vec![base.clone()];
        for (field, value) in [
            ("PID", json!(43)),
            ("Source file", json!("analyses/other/pid.42.dmp")),
            ("Kind", json!("Web search")),
            ("Kind", json!("Session tab")),
            ("Kind", json!("Memory URL")),
        ] {
            let mut row = base.clone();
            row.fields.insert(field.into(), value);
            rows.push(row);
        }
        rows.extend([
            query("https://www.bing.com/search?q=tea+recipe&FORM=ANNTA1", 0),
            query("https://cn.bing.com/search?q=tea+recipe", 0),
            query("https://www.google.com/search?q=tea+recipe", 0),
            query("https://rumble.com/search?q=tea", 0),
            query("https://rumble.com/search/video?q=tea+recipe", 0),
        ]);
        let originals: Vec<_> = rows.iter().map(|r| r.fields.clone()).collect();
        memory_searches(&mut rows);
        assert_eq!(
            rows.iter().map(|r| r.fields.clone()).collect::<Vec<_>>(),
            originals
        );
    }
}
