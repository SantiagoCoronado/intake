//! Tests for ContextWindowBuilder — mirrors `tests/test_context.py`.

use intake_core::{Channel, ContextWindowBuilder, TaggedInput, TrustLevel, TRUST_PROTOCOL_PREAMBLE};

fn make_input(content: &str, channel: Channel, trust: TrustLevel) -> TaggedInput {
    TaggedInput::new(content, channel, trust).with_id("test-id-001")
}

#[test]
fn test_system_preamble_is_first_message() {
    let builder = ContextWindowBuilder::new("You are a helpful assistant.", None);
    let messages = builder.build();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].role, "system");
    assert!(messages[0].content.contains(TRUST_PROTOCOL_PREAMBLE));
    assert!(messages[0].content.contains("helpful assistant"));
}

#[test]
fn test_trust_delimiters_wrap_content() {
    let mut builder = ContextWindowBuilder::new("You are a helpful assistant.", None);
    let tagged = TaggedInput::new("Hello world", Channel::ExternalEmail, TrustLevel::Untrusted)
        .with_id("abc123")
        .with_source("email from alice@corp.com");

    builder.add_input(&tagged, "user");
    let messages = builder.build();
    assert_eq!(messages.len(), 2);

    let user_msg = &messages[1];
    assert_eq!(user_msg.role, "user");
    assert!(user_msg.content.contains(r#"<intake channel="external_email""#));
    assert!(user_msg.content.contains(r#"trust="untrusted""#));
    assert!(user_msg.content.contains(r#"id="abc123""#));
    assert!(user_msg.content.contains(r#"source="email from alice@corp.com""#));
    assert!(user_msg.content.contains("Hello world"));
    assert!(user_msg.content.contains("</intake>"));
}

#[test]
fn test_multiple_inputs_ordered() {
    let mut builder = ContextWindowBuilder::new("", None);
    let a = make_input("first", Channel::OwnerCli, TrustLevel::Owner);
    let b = make_input("second", Channel::ExternalEmail, TrustLevel::Untrusted);
    builder.add_input(&a, "user");
    builder.add_input(&b, "user");
    let messages = builder.build();
    assert_eq!(messages.len(), 3); // system + 2 user
    assert!(messages[1].content.contains("first"));
    assert!(messages[2].content.contains("second"));
}

#[test]
fn test_assistant_message_added() {
    let mut builder = ContextWindowBuilder::new("", None);
    builder.add_assistant_message("I can help with that.");
    let messages = builder.build();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[1].role, "assistant");
    assert_eq!(messages[1].content, "I can help with that.");
}

#[test]
fn test_max_untrusted_tokens_truncates() {
    let mut builder = ContextWindowBuilder::new("", Some(10)); // ~40 chars
    let long_content = "A".repeat(200);
    let tagged = TaggedInput::new(&long_content, Channel::ExternalEmail, TrustLevel::Untrusted)
        .with_id("trunc-id");
    builder.add_input(&tagged, "user");
    let messages = builder.build();
    let content = &messages[1].content;
    assert!(content.contains("[TRUNCATED"));
    assert!(content.len() < long_content.len() + 200);
}

#[test]
fn test_max_untrusted_tokens_does_not_truncate_trusted() {
    let mut builder = ContextWindowBuilder::new("", Some(10));
    let long_content = "A".repeat(200);
    let tagged =
        TaggedInput::new(&long_content, Channel::OwnerCli, TrustLevel::Owner).with_id("owner-id");
    builder.add_input(&tagged, "user");
    let messages = builder.build();
    assert!(!messages[1].content.contains("[TRUNCATED"));
    assert!(messages[1].content.contains(&"A".repeat(200)));
}

#[test]
fn test_source_with_quotes_escaped() {
    let mut builder = ContextWindowBuilder::new("", None);
    let tagged = TaggedInput::new("test", Channel::ExternalEmail, TrustLevel::Untrusted)
        .with_id("quote-id")
        .with_source(r#"Bob "The Builder""#);
    builder.add_input(&tagged, "user");
    let messages = builder.build();
    assert!(messages[1].content.contains("&quot;"));
}

#[test]
fn test_clear() {
    let mut builder = ContextWindowBuilder::new("", None);
    let tagged = make_input("test", Channel::OwnerCli, TrustLevel::Owner);
    builder.add_input(&tagged, "user");
    assert_eq!(builder.get_messages().len(), 1);
    builder.clear();
    assert_eq!(builder.get_messages().len(), 0);
}

#[test]
fn test_empty_preamble() {
    let builder = ContextWindowBuilder::new("", None);
    let messages = builder.build();
    assert_eq!(messages[0].content, TRUST_PROTOCOL_PREAMBLE);
}

#[test]
fn test_owner_input_tagged_as_owner() {
    let mut builder = ContextWindowBuilder::new("", None);
    let tagged = make_input("admin command", Channel::OwnerCli, TrustLevel::Owner);
    builder.add_input(&tagged, "user");
    let messages = builder.build();
    assert!(messages[1].content.contains(r#"trust="owner""#));
}
