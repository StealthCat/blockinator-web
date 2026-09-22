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
