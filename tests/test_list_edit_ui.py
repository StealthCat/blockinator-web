from pathlib import Path


def test_blocklist_and_whitelist_cards_link_to_dedicated_edit_pages():
    source = Path("app/main.py").read_text(encoding="utf-8")

    assert 'href="{base_path}/{int(r["id"])}/edit">Edit</a>' in source
    assert '<details class="list-editor"' not in source
    assert 'href="#edit-list-' not in source


def test_dedicated_edit_routes_exist_for_blocklists_and_whitelists():
    source = Path("app/main.py").read_text(encoding="utf-8")

    assert '@app.get("/lists/{list_id}/edit", response_class=HTMLResponse)' in source
    assert '@app.get("/whitelists/{list_id}/edit", response_class=HTMLResponse)' in source
    assert 'def managed_list_edit_page(list_id: int, request: Request):' in source


def test_dedicated_list_editor_contains_existing_edit_controls():
    source = Path("app/main.py").read_text(encoding="utf-8")

    assert 'class="managed-list-edit-page"' in source
    assert 'class="list-edit-hero"' in source
    assert 'class="list-edit-section-nav"' in source
    assert 'class="list-edit-status-grid"' in source
    assert 'id="general"' in source
    assert 'id="policy-targeting"' in source
    assert 'id="schedule"' in source
    assert 'id="import-update"' in source
    assert 'id="preview"' in source
    assert 'action="/admin/lists/{list_id}/edit"' in source
    assert 'action="/admin/lists/{list_id}/delete"' in source
    assert 'name="source_url"' in source
    assert 'name="refresh_minutes"' in source
    assert 'name="global_list"' in source
    assert 'name="replacement_file"' in source
    assert 'name="replacement_text"' in source
    assert 'name="action" value="refresh"' in source
    assert 'data-scope-assignments' in source
    assert 'data-schedule-editor' in source
    assert 'SELECT domain' in source
    assert 'LIMIT 10' in source


def test_edit_post_redirects_back_to_dedicated_editor():
    source = Path("app/main.py").read_text(encoding="utf-8")

    assert 'return redirect(f"{base_path}/{list_id}/edit", error=str(e))' in source
    assert 'f"{base_path}/{list_id}/edit",\n        notice=f"Saved {name}' in source


def test_rendered_list_editor_styles_and_navigation_are_wired():
    css = Path("app/static/style.css").read_text(encoding="utf-8")
    javascript = Path("app/static/app.js").read_text(encoding="utf-8")

    assert ".list-edit-status-grid" in css
    assert ".list-edit-workspace" in css
    assert ".list-edit-preview" in css
    assert ".list-edit-savebar" in css
    assert ".main:has(.managed-list-edit-page)" in css
    assert "initializeListEditNavigation" in javascript


def test_list_editor_uses_theme_aware_palette():
    css = Path("app/static/style.css").read_text(encoding="utf-8")

    assert '[data-theme="dark"] .list-edit-card' in css
    assert '[data-theme="dark"] .list-edit-section-nav' in css
    assert '[data-theme="light"] .main:has(.managed-list-edit-page)' not in css

def test_manual_domain_add_returns_to_unfiltered_full_list():
    source = Path("app/main.py").read_text(encoding="utf-8")
    start = source.index("async def add_manual_list_domain")
    end = source.index('@app.post("/admin/lists/{list_id}/domains/remove")', start)
    handler = source[start:end]

    assert 'f"{base_path}/{list_id}/domains",' in handler
    assert 'notice=f"Added {domain}; manual list now contains {count:,} domains"' in handler
    assert 'f"{base_path}/{list_id}/domains?q={quote(domain)}",' in handler
    assert handler.count('f"{base_path}/{list_id}/domains?q={quote(domain)}",') == 1

def test_manual_domain_back_link_returns_to_list_editor():
    source = Path("app/main.py").read_text(encoding="utf-8")
    start = source.index("def manual_list_domains_page")
    end = source.index('@app.post("/admin/lists/{list_id}/domains/add")', start)
    page = source[start:end]

    assert 'href="{base_path}/{list_id}/edit">← Back to edit ' in page
    assert 'href="{base_path}#list-{list_id}">← Back to ' not in page

