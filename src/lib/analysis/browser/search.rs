//! Recognize result-page URLs, not arbitrary `q` parameters or autocomplete APIs.
struct Provider {
    name: &'static str,
    hosts: &'static [&'static str],
    paths: &'static [&'static str],
    parameter: &'static str,
}

const PROVIDERS: &[Provider] = &[
    Provider {
        name: "Brave",
        hosts: &["search.brave.com"],
        paths: &["/search"],
        parameter: "q",
    },
    Provider {
        name: "Search",
        hosts: &["search.com"],
        paths: &["/web"],
        parameter: "q",
    },
    Provider {
        name: "DuckDuckGo",
        hosts: &[
            "duckduckgo.com",
            "html.duckduckgo.com",
            "lite.duckduckgo.com",
            "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
            "3g2upl4pq6kufc4m.onion",
        ],
        paths: &["", "/html", "/lite"],
        parameter: "q",
    },
    Provider {
        name: "WebCrawler",
        hosts: &["webcrawler.com"],
        paths: &["/serp", "/search"],
        parameter: "q",
    },
    Provider {
        name: "Ecosia",
        hosts: &["ecosia.org"],
        paths: &["/search"],
        parameter: "q",
    },
    Provider {
        name: "Excite",
        hosts: &[
            "excite.com",
            "search.excite.com",
            "results.excite.com",
            "msxml.excite.com",
        ],
        paths: &["/serp", "/search/web/results"],
        parameter: "q",
    },
    Provider {
        name: "Rumble",
        hosts: &["rumble.com"],
        paths: &["/search", "/search/video", "/search/all", "/search/channel"],
        parameter: "q",
    },
    Provider {
        name: "YouTube",
        hosts: &["youtube.com", "m.youtube.com"],
        paths: &["/results"],
        parameter: "search_query",
    },
    Provider {
        name: "Yandex",
        hosts: &[
            "yandex.com",
            "yandex.ru",
            "yandex.com.tr",
            "yandex.kz",
            "yandex.by",
            "yandex.uz",
        ],
        paths: &["/search", "/yandsearch"],
        parameter: "text",
    },
    Provider {
        name: "Bing",
        hosts: &["bing.com", "cn.bing.com"],
        paths: &["/search"],
        parameter: "q",
    },
    Provider {
        name: "Info",
        hosts: &["info.com"],
        paths: &["/serp"],
        parameter: "q",
    },
    Provider {
        name: "Ask",
        hosts: &["ask.com", "search.ask.com"],
        paths: &["/web"],
        parameter: "q",
    },
    Provider {
        name: "Google",
        hosts: &[
            "google.com",
            "google.com.au",
            "google.co.uk",
            "google.co.in",
            "google.ca",
            "google.de",
            "google.fr",
            "google.co.jp",
            "google.co.nz",
        ],
        paths: &["/search"],
        parameter: "q",
    },
    // Retain support for existing cases using Yahoo.
    Provider {
        name: "Yahoo",
        hosts: &["search.yahoo.com"],
        paths: &["/search"],
        parameter: "p",
    },
];

/// This decodes a URL observation. It does not establish who entered the query.
pub(in crate::analysis) fn search_terms(address: &str) -> Option<(String, String)> {
    let url = url::Url::parse(address).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    let host = url.host_str()?.to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host);
    let path = url.path().trim_end_matches('/');
    let provider = PROVIDERS
        .iter()
        .find(|p| p.hosts.contains(&host) && p.paths.contains(&path))?;
    let term = url
        .query_pairs()
        .find(|(key, _)| key == provider.parameter)?
        .1
        .into_owned();
    if term.trim().is_empty()
        || term.contains(['{', '}'])
        || matches!(term.as_str(), "%s" | "%S")
        || term.chars().any(char::is_control)
    {
        return None;
    }
    Some((provider.name.into(), term))
}

/// Recognize known Edge annotation URLs without claiming who typed a query.
pub(in crate::analysis) fn query_origin(url: &url::Url) -> &'static str {
    if matches!(url.host_str(), Some("bing.com" | "www.bing.com"))
        && url.path() == "/search"
        && url.query_pairs().any(|(key, value)| {
            key.eq_ignore_ascii_case("form")
                && matches!(value.to_ascii_uppercase().as_str(), "ANNTA1" | "ANSPA1")
        })
    {
        "Automated Edge annotation URL"
    } else {
        "Unknown; typed input not established"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edge_annotations_are_flagged_and_other_queries_do_not_imply_typing() {
        assert_eq!(
            query_origin(
                &url::Url::parse("https://www.bing.com/search?q=tea&FORM=ANNTA1").unwrap()
            ),
            "Automated Edge annotation URL"
        );
        assert_eq!(
            query_origin(
                &url::Url::parse("https://www.bing.com/search?q=tea&form=anspa1").unwrap()
            ),
            "Automated Edge annotation URL"
        );
        assert_eq!(
            query_origin(&url::Url::parse("https://www.search.com/web?q=tea").unwrap()),
            "Unknown; typed input not established"
        );
        assert_eq!(
            query_origin(
                &url::Url::parse("https://www.bing.com.evil.test/search?q=tea&FORM=ANNTA1")
                    .unwrap()
            ),
            "Unknown; typed input not established"
        );
    }

    #[test]
    fn all_requested_providers_decode_their_own_query_parameter() {
        for (provider, url) in [
            ("Brave", "https://search.brave.com/search?q=what+is+gluten"),
            ("Search", "https://www.search.com/web?q=what+is+gluten"),
            ("DuckDuckGo", "https://duckduckgo.com/?q=what+is+gluten"),
            (
                "WebCrawler",
                "https://www.webcrawler.com/serp?q=what+is+gluten",
            ),
            ("Ecosia", "https://www.ecosia.org/search?q=what+is+gluten"),
            ("Excite", "https://results.excite.com/serp?q=what+is+gluten"),
            ("Rumble", "https://rumble.com/search/video?q=what+is+gluten"),
            (
                "YouTube",
                "https://www.youtube.com/results?search_query=what+is+gluten",
            ),
            ("Yandex", "https://yandex.com/search/?text=what+is+gluten"),
            ("Bing", "https://www.bing.com/search?q=what+is+gluten"),
            ("Info", "https://www.info.com/serp?q=what+is+gluten"),
            ("Ask", "https://www.ask.com/web?q=what+is+gluten"),
            ("Google", "https://www.google.com/search?q=what+is+gluten"),
        ] {
            assert_eq!(
                search_terms(url),
                Some((provider.into(), "what is gluten".into())),
                "{url}"
            );
            let encoded = url.replace("what+is+gluten", "caf%C3%A9%20%2B%20tea");
            assert_eq!(
                search_terms(&encoded),
                Some((provider.into(), "café + tea".into()))
            );
            let spoofed = url.replace(
                url::Url::parse(url).unwrap().host_str().unwrap(),
                "www.google.com.evil.test",
            );
            assert!(search_terms(&spoofed).is_none(), "{spoofed}");
        }
    }

    #[test]
    fn rejects_resource_and_suggestion_urls_templates_and_wrong_parameters() {
        for url in [
            "https://duckduckgo.com/t.js?q=suggested",
            "https://ac.ecosia.org/autocomplete?q=gluten",
            "https://suggest.yandex.com/suggest-ff.cgi?part=gluten",
            "https://www.youtube.com/watch?search_query=gluten",
            "https://www.youtube.com/results?q=gluten",
            "https://yandex.com/search/?q=gluten",
            "https://www.google.com/search?q=%7BsearchTerms%7D",
            "https://duckduckgo.com/?q=%s",
            "https://www.bing.com/search?q=+%20",
            "https://example.com/?q=gluten",
            "https://www.google.com@evil.test/search?q=gluten",
            "file://www.google.com/search?q=gluten",
            "https://www.google.com/search?q=gluten%00suffix",
        ] {
            assert!(search_terms(url).is_none(), "{url}");
        }
    }

    #[test]
    fn supports_mobile_regional_onion_and_legacy_variants() {
        for (provider, url) in [
            ("DuckDuckGo", "https://html.duckduckgo.com/html/?q=tea"),
            (
                "DuckDuckGo",
                "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/?q=tea",
            ),
            ("YouTube", "https://m.youtube.com/results?search_query=tea"),
            ("Google", "https://www.google.co.uk/search?q=tea"),
            ("Yandex", "https://yandex.ru/yandsearch?text=tea"),
            ("Excite", "http://msxml.excite.com/serp?q=tea"),
            ("Ask", "http://search.ask.com/web?q=tea"),
            ("Yahoo", "https://search.yahoo.com/search?p=tea"),
        ] {
            assert_eq!(
                search_terms(url),
                Some((provider.into(), "tea".into())),
                "{url}"
            );
        }
    }
}
