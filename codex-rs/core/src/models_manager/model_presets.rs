/// Legacy notice keys kept for config compatibility with older migration prompts.
///
/// Hardcoded model presets were removed; model listings are now derived from the active catalog.
pub const HIDE_GPT5_1_MIGRATION_PROMPT_CONFIG: &str = "hide_gpt5_1_migration_prompt";
pub const HIDE_GPT_5_1_CODEX_MAX_MIGRATION_PROMPT_CONFIG: &str =
    "hide_gpt-5.1-codex-max_migration_prompt";

fn gpt_53_codex_spark_upgrade() -> ModelUpgrade {
    ModelUpgrade {
        id: "gpt-5.3-codex-spark".to_string(),
        reasoning_effort_mapping: None,
        migration_config_key: "gpt-5.3-codex-spark".to_string(),
        model_link: None,
        upgrade_copy: Some(
            "Codex is now powered by gpt-5.3-codex-spark, our latest frontier agentic coding model. It is smarter and faster than its predecessors and capable of long-running project-scale work."
                .to_string(),
        ),
        migration_markdown: Some(
            indoc! {r#"
                **Codex just got an upgrade. Introducing {model_to}.**

                Codex is now powered by gpt-5.3-codex-spark, our latest frontier agentic coding model. It is smarter and faster than its predecessors and capable of long-running project-scale work.

                You can continue using {model_from} if you prefer.
            "#}
            .to_string(),
        ),
    }
}
