use catbird_mls::orchestrator;

fn assert_same_type<T>(_: T, _: T) {}

#[test]
fn message_processing_result_legacy_paths_remain_exported() {
    let from_root: Option<catbird_mls::MessageProcessingResult> = None;
    let from_engine: Option<catbird_mls::engine::MessageProcessingResult> = None;
    let from_orchestrator: Option<orchestrator::MessageProcessingResult> = None;

    assert_same_type(from_root, from_orchestrator);
    assert_same_type(from_engine, None::<orchestrator::MessageProcessingResult>);
}
