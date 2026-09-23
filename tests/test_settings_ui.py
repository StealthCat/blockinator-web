from pathlib import Path


def test_system_settings_has_tabbed_configuration_areas():
    source = Path("app/main.py").read_text(encoding="utf-8")

    assert 'data-settings-tab="general"' in source
    assert 'data-settings-tab="tls"' in source
    assert 'data-settings-tab="runtime"' in source
    assert 'data-settings-panel="general"' in source
    assert 'data-settings-panel="tls"' in source
    assert 'data-settings-panel="runtime"' in source


def test_tls_settings_render_one_mode_fieldset_at_a_time():
    source = Path("app/main.py").read_text(encoding="utf-8")
    javascript = Path("app/static/app.js").read_text(encoding="utf-8")

    assert 'data-tls-mode-fields="http"' in source
    assert 'data-tls-mode-fields="upload"' in source
    assert 'data-tls-mode-fields="acme"' in source
    assert 'fieldset.hidden = !active;' in javascript
    assert 'fieldset.disabled = !active;' in javascript
    assert 'data-tls-mode-description' in source


def test_system_settings_exposes_unmatched_scope_default_action():
    source = Path("app/main.py").read_text(encoding="utf-8")

    assert 'name="unmatched_scope_action"' in source
    assert '<option value="allow"' in source
    assert '<option value="deny"' in source
    assert 'No matching policy target' in source


def test_system_settings_exposes_global_blocklist_scope_mode():
    source = Path("app/main.py").read_text(encoding="utf-8")

    assert 'name="global_blocklist_scope_mode"' in source
    assert 'value="all_clients"' in source
    assert 'value="matched_scopes"' in source
    assert 'Global list reach' in source

def test_dashboard_reason_prefers_triggering_blocklist_name():
    source = Path("app/main.py").read_text(encoding="utf-8")

    assert "matched_scope,matched_list,matched_list_type,policy_scheme" in source
    assert 'decision_match_text(r)' in source

