import json
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import pytest

from app.db import Database
from app.policy import _compile_schedule
from app.inspector import next_transition
from app.schedules import extra_schedule_windows
from test_dev_review import web


EXTRAS = [{'days': list(range(5)), 'start': '18:00', 'end': '00:00'},
          {'days': [5, 6], 'start': '00:00', 'end': '10:00'},
          {'days': [5, 6], 'start': '18:00', 'end': '00:00'}]


def local(day, hour, minute=0):
    return datetime(2026, 10, day, hour, minute, tzinfo=ZoneInfo('America/New_York'))


def test_requested_weekday_weekend_windows_every_minute():
    schedule = _compile_schedule(True, frozenset(range(5)), '00:00', '17:00', 'America/New_York', json.dumps(EXTRAS))
    # Complete week including exact start/end boundaries and Sunday -> Monday.
    for day in range(5, 12):
        for minute in range(24 * 60):
            now = local(day, minute // 60, minute % 60)
            expected = (not 17 * 60 <= minute < 18 * 60) if now.weekday() < 5 else (minute < 10 * 60 or minute >= 18 * 60)
            assert schedule.is_active(now) == expected, now


def test_overnight_overlap_and_dst_transition():
    schedule = _compile_schedule(True, frozenset({5}), '18:00', '08:00', 'America/New_York',
        json.dumps([{'days':[6], 'start':'08:00','end':'10:00'}]))
    # DST ends Nov 1; both occurrences of 01:30 remain inside Saturday's window.
    for fold in (0, 1):
        assert schedule.is_active(datetime(2026,11,1,1,30,tzinfo=ZoneInfo('America/New_York'),fold=fold))
    now = datetime(2026,11,1,7,30,tzinfo=ZoneInfo('America/New_York'))
    assert next_transition(schedule, now) == datetime(2026,11,1,15,tzinfo=timezone.utc)
    overlap = _compile_schedule(True, frozenset({0}), '08:00','12:00','UTC',
        json.dumps([{'days':[0], 'start':'10:00','end':'14:00'}]))
    assert next_transition(overlap, datetime(2026,10,5,9,tzinfo=timezone.utc)) == datetime(2026,10,5,14,tzinfo=timezone.utc)


@pytest.mark.parametrize('value', ['{}', '[null]', '[{"days":[],"start":"08:00","end":"09:00"}]',
    '[{"days":[7],"start":"08:00","end":"09:00"}]', '[{"days":[0],"start":"25:00","end":"09:00"}]',
    '[{"days":[0],"start":"08:00:00","end":"09:00"}]', json.dumps([EXTRAS[0]]*32)])
def test_malformed_windows_are_rejected_and_inactive(value):
    with pytest.raises(ValueError):
        extra_schedule_windows(value)
    schedule = _compile_schedule(True, frozenset(range(7)), '00:00','00:00','UTC',value)
    assert not schedule.valid and not schedule.is_active(local(5, 12))


def form_data(session):
    data = {'csrf_token':session.csrf_token,'schedule_enabled':'1','schedule_day':['0','1','2','3','4'],
            'schedule_start':'00:00','schedule_end':'17:00','schedule_timezone':'America/New_York',
            'schedule_window':['1','2','3']}
    for i, window in enumerate(EXTRAS, 1):
        data.update({f'schedule_day_{i}':list(map(str,window['days'])), f'schedule_start_{i}':window['start'], f'schedule_end_{i}':window['end']})
    return data


@pytest.mark.parametrize('kind', ['block', 'whitelist', 'target', 'whitelist-target'])
def test_save_edit_reload_and_render_windows(web, kind):
    main, client, session = web
    data = form_data(session)
    target = kind.endswith('target')
    if target:
        data.update(name='Scheduled',kind='client',target='192.0.2.8',whitelisted='1' if kind=='whitelist-target' else '0')
        table, url = 'scopes', '/admin/scopes'
    else:
        data.update(name='Scheduled',text='youtube.com',format='domains',list_type=kind,global_list='1')
        table, url = 'blocklists', '/admin/lists'
    response = client.post(url, data=data)
    assert response.status_code == 303 and 'error=' not in response.headers['location']
    with main.db.connect() as con:
        row = con.execute(f'SELECT * FROM {table} WHERE name=?',('Scheduled',)).fetchone()
        object_id = row['id']
        assert json.loads(row['schedule_windows']) == EXTRAS
    def active():
        if target:
            return main.engine.snapshot.client_scopes['192.0.2.8'][0].schedule
        return next(item.schedule for item in main.engine.snapshot.list_order if item.id==object_id)
    for reload in (main.engine.reload, main.engine.reload_lists, main.engine.reload_scopes):
        reload()
        assert active().is_active(local(10, 9))
        assert not active().is_active(local(10, 12))
    get_url = f'/scopes/{object_id}/edit' if target else f'/{"whitelists" if kind=="whitelist" else "lists"}/{object_id}/edit'
    html = client.get(get_url).text
    assert 'Add time window' in html and 'name="schedule_start_3"' in html
    # Remove one extra row through the normal edit route and preserve others.
    data['schedule_window'] = ['1','2']
    if not target:
        data.update(enabled='1',source_type='text',action='save')
    response = client.post(f'{url}/{object_id}/edit',data=data)
    assert response.status_code == 303 and 'error=' not in response.headers['location']
    with main.db.connect() as con:
        assert len(json.loads(con.execute(f'SELECT schedule_windows FROM {table} WHERE id=?',(object_id,)).fetchone()['schedule_windows'])) == 2
    # Invalid windows must not partially save a changed name or schedule.
    data.update(name='Should not save',schedule_start_2='99:00')
    response = client.post(f'{url}/{object_id}/edit',data=data)
    assert 'error=' in response.headers['location']
    with main.db.connect() as con:
        assert con.execute(f'SELECT name FROM {table} WHERE id=?',(object_id,)).fetchone()['name']=='Scheduled'


def test_legacy_database_schedule_is_preserved(tmp_path):
    db = Database(str(tmp_path / 'legacy.db'))
    with db.connect() as con:
        for table in ('blocklists','scopes'):
            con.execute(f'ALTER TABLE {table} DROP COLUMN schedule_windows')
        con.execute("INSERT INTO scopes(name,kind,target,schedule_enabled,schedule_start,schedule_end) VALUES('Legacy','client','192.0.2.9',1,'08:00','10:00')")
    db.initialize()
    with db.connect() as con:
        row = con.execute('SELECT * FROM scopes').fetchone()
        assert row['schedule_start']=='08:00' and row['schedule_end']=='10:00' and row['schedule_windows'] is None
