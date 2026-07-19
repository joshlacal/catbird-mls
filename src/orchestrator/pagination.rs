use std::collections::HashSet;

use super::error::{OrchestratorError, Result};

/// Hard limits for server-controlled conversation pagination.
///
/// Conversation listings are a recovery and synchronization input, so a
/// remote peer must not be able to keep a client in an unbounded cursor loop
/// or make it retain an unbounded result set. Ten thousand conversations is
/// deliberately well above normal client use while keeping memory and network
/// work finite.
pub(crate) const MAX_CONVERSATION_PAGES: usize = 100;
pub(crate) const MAX_CONVERSATION_ITEMS: usize = 10_000;

/// Tracks a single cursor-pagination traversal and rejects remote responses
/// that would make it unbounded.
#[derive(Debug)]
pub(crate) struct PaginationGuard {
    context: &'static str,
    max_pages: usize,
    max_items: usize,
    pages: usize,
    items: usize,
    seen_cursors: HashSet<String>,
}

impl PaginationGuard {
    pub(crate) fn for_conversations(context: &'static str) -> Self {
        Self::with_limits(context, MAX_CONVERSATION_PAGES, MAX_CONVERSATION_ITEMS)
    }

    fn with_limits(context: &'static str, max_pages: usize, max_items: usize) -> Self {
        debug_assert!(max_pages > 0);
        debug_assert!(max_items > 0);
        Self {
            context,
            max_pages,
            max_items,
            pages: 0,
            items: 0,
            seen_cursors: HashSet::new(),
        }
    }

    /// Record one response page before its items are retained or processed.
    ///
    /// A continuation cursor on the final permitted page is rejected so the
    /// caller fails before issuing a request beyond the page ceiling. Every
    /// cursor is remembered, which catches both immediate repeats and longer
    /// cycles such as A -> B -> A.
    pub(crate) fn observe_page(
        &mut self,
        item_count: usize,
        next_cursor: Option<&str>,
    ) -> Result<()> {
        self.pages = self.pages.checked_add(1).ok_or_else(|| {
            OrchestratorError::Api(format!(
                "{} pagination page counter overflowed",
                self.context
            ))
        })?;
        if self.pages > self.max_pages {
            return Err(OrchestratorError::Api(format!(
                "{} pagination exceeded the {} page limit",
                self.context, self.max_pages
            )));
        }

        self.items = self.items.checked_add(item_count).ok_or_else(|| {
            OrchestratorError::Api(format!(
                "{} pagination item counter overflowed",
                self.context
            ))
        })?;
        if self.items > self.max_items {
            return Err(OrchestratorError::Api(format!(
                "{} pagination exceeded the {} item limit",
                self.context, self.max_items
            )));
        }

        let Some(cursor) = next_cursor else {
            return Ok(());
        };
        if cursor.is_empty() {
            return Err(OrchestratorError::Api(format!(
                "{} pagination returned an empty continuation cursor",
                self.context
            )));
        }
        if !self.seen_cursors.insert(cursor.to_string()) {
            return Err(OrchestratorError::Api(format!(
                "{} pagination repeated a continuation cursor",
                self.context
            )));
        }
        if self.pages == self.max_pages {
            return Err(OrchestratorError::Api(format!(
                "{} pagination still had a continuation cursor at the {} page limit",
                self.context, self.max_pages
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_api_error(result: Result<()>, expected: &str) {
        match result {
            Err(OrchestratorError::Api(message)) => assert!(
                message.contains(expected),
                "expected {expected:?} in {message:?}"
            ),
            other => panic!("expected API pagination error, got {other:?}"),
        }
    }

    #[test]
    fn accepts_a_finite_multi_page_traversal_at_the_limits() {
        let mut guard = PaginationGuard::with_limits("test", 2, 3);
        guard.observe_page(2, Some("next")).unwrap();
        guard.observe_page(1, None).unwrap();
    }

    #[test]
    fn rejects_an_immediately_repeated_cursor() {
        let mut guard = PaginationGuard::with_limits("test", 4, 10);
        guard.observe_page(1, Some("same")).unwrap();
        assert_api_error(guard.observe_page(1, Some("same")), "repeated");
    }

    #[test]
    fn rejects_a_longer_cursor_cycle() {
        let mut guard = PaginationGuard::with_limits("test", 5, 10);
        guard.observe_page(1, Some("a")).unwrap();
        guard.observe_page(1, Some("b")).unwrap();
        assert_api_error(guard.observe_page(1, Some("a")), "repeated");
    }

    #[test]
    fn rejects_continuation_at_the_page_ceiling() {
        let mut guard = PaginationGuard::with_limits("test", 2, 10);
        guard.observe_page(1, Some("a")).unwrap();
        assert_api_error(guard.observe_page(1, Some("b")), "page limit");
    }

    #[test]
    fn rejects_an_oversized_total_before_items_are_processed() {
        let mut guard = PaginationGuard::with_limits("test", 3, 3);
        guard.observe_page(2, Some("a")).unwrap();
        assert_api_error(guard.observe_page(2, None), "item limit");
    }

    #[test]
    fn rejects_an_empty_continuation_cursor() {
        let mut guard = PaginationGuard::with_limits("test", 3, 3);
        assert_api_error(guard.observe_page(1, Some("")), "empty continuation");
    }
}
