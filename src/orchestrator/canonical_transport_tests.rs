use super::canonical_transport::{canonical_route, route_for_nsid, CanonicalOperation};

#[test]
fn canonical_routes_never_emit_the_legacy_mls_chat_namespace() {
    for operation in CanonicalOperation::ALL {
        let route = canonical_route(*operation);
        assert!(
            route.nsid.starts_with("blue.catbird.chat."),
            "{} still routes through the legacy namespace",
            route.nsid
        );
        assert_eq!(route.path, format!("/xrpc/{}", route.nsid));
    }
}

#[test]
fn canonical_generated_query_uses_the_generated_page_cursor_shape() {
    use crate::atproto::blue_catbird::chat::get_conversations::GetConversations;

    let request = GetConversations {
        limit: 25,
        page_cursor: Some("opaque-cursor".to_owned()),
    };
    let value = serde_json::to_value(request).expect("generated request serializes");
    assert_eq!(value["limit"], 25);
    assert_eq!(value["pageCursor"], "opaque-cursor");
    assert!(value.get("cursor").is_none());
}

#[test]
fn canonical_route_inventory_covers_only_generated_endpoints() {
    let expected = [
        (
            CanonicalOperation::GetConversations,
            "blue.catbird.chat.getConversations",
        ),
        (
            CanonicalOperation::CreateConversation,
            "blue.catbird.chat.createConversation",
        ),
        (
            CanonicalOperation::SendMessage,
            "blue.catbird.chat.sendMessage",
        ),
        (
            CanonicalOperation::GetEntries,
            "blue.catbird.chat.getEntries",
        ),
        (
            CanonicalOperation::ReplenishKeyPackages,
            "blue.catbird.chat.replenishKeyPackages",
        ),
        (
            CanonicalOperation::EnrollDevice,
            "blue.catbird.chat.enrollDevice",
        ),
        (
            CanonicalOperation::RequestLeave,
            "blue.catbird.chat.requestLeave",
        ),
        (
            CanonicalOperation::SubmitTransition,
            "blue.catbird.chat.submitTransition",
        ),
    ];

    for (operation, nsid) in expected {
        assert_eq!(canonical_route(operation).nsid, nsid);
    }
}

#[test]
fn legacy_nsid_is_not_accepted_as_a_canonical_route() {
    assert!(route_for_nsid("blue.catbird.mlsChat.getMessages").is_none());
    assert!(route_for_nsid("blue.catbird.mlsChat.sendMessage").is_none());
    assert_eq!(
        route_for_nsid("blue.catbird.chat.getEntries").map(|route| route.path),
        Some("/xrpc/blue.catbird.chat.getEntries")
    );
}
