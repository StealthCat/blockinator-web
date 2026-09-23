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
    assert 'action="/admin/lists/{list_id}/edit"' in source
    assert 'name="source_url"' in source
    assert 'name="refresh_minutes"' in source
    assert 'name="global_list"' in source
    assert 'name="replacement_file"' in source
    assert 'name="replacement_text"' in source
    assert 'name="action" value="refresh"' in source
    assert 'data-scope-assignments' in source
    assert 'data-schedule-editor' in source


def test_edit_post_redirects_back_to_dedicated_editor():
    source = Path("app/main.py").read_text(encoding="utf-8")

    assert 'return redirect(f"{base_path}/{list_id}/edit", error=str(e))' in source
    assert 'f"{base_path}/{list_id}/edit",\n        notice=f"Saved {name}' in source
