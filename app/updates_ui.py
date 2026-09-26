"""Server-rendered update controls; all host operations remain behind the updater socket."""
import html
from .updates import updater_request
from .version import APP_VERSION, BUILD_CHANNEL, BUILD_SHA


def esc(value):
    return html.escape(str(value if value is not None else ""), quote=True)


def render_updates(csrf):
    try:
        status = updater_request()
        unavailable = ""
    except ValueError as exc:
        status = {}
        unavailable = str(exc)
    settings = status.get("settings") or {"channel": "release", "mode": "notify", "hour": 3, "timezone": "UTC"}
    candidate, previous = status.get("candidate"), status.get("previous")
    current = status.get("current") or {"version": APP_VERSION, "channel": BUILD_CHANNEL, "sha": BUILD_SHA}
    disabled = " disabled" if unavailable else ""
    def options(values, selected):
        return "".join(f'<option value="{esc(value)}"{" selected" if value == selected else ""}>{esc(label)}</option>' for value, label in values)
    def action(name, label, digest="", blocked=False):
        return f'<form method="post" action="/admin/updates"><input type="hidden" name="csrf_token" value="{esc(csrf)}"><input type="hidden" name="action" value="{name}"><input type="hidden" name="digest" value="{esc(digest)}"><button class="small-button"{disabled}{" disabled" if blocked and not disabled else ""}>{label}</button></form>'
    latest = (f'{candidate["version"]} · {candidate["channel"]} · {candidate["sha"][:12]}' if candidate else "Check for a published build")
    history = "".join(f'<tr><td>{esc(row["time"])}</td><td>{esc(row["version"])}</td><td>{esc(row["result"])}</td><td>{esc(row.get("error"))}</td></tr>' for row in reversed(status.get("history") or []))
    note = f'<div class="flash bad">{esc(unavailable)}</div>' if unavailable else ""
    current_image = current.get("image")
    verification = ("GitHub provenance (gh)" if status.get("backend") == "gh" else
                    "Trusted GitHub repository metadata (git); attestations are not checked" if status.get("backend") == "git" else
                    "Host service unavailable" if unavailable else "See host configuration")
    return f'''<section id="settings-updates" class="settings-tab-panel" role="tabpanel" aria-labelledby="settings-tab-updates" data-settings-panel="updates" hidden>
      <section class="panel action-panel" data-update-controls data-update-candidate="{esc(candidate["digest"] if candidate else "")}" data-update-current="{esc(current["sha"])}">
        <div class="panel-kicker">Application updates</div><h3>Release channels</h3>
        <p class="panel-help">Release delivers approved stable builds. Preview delivers tested changes before stable promotion. Installation briefly interrupts policy service.</p>
        {note}
        <div class="info-grid">
          <div><span>Installed</span><b>{esc(current["version"])} · {esc(current.get("channel", BUILD_CHANNEL))} · {esc(current["sha"][:12])}</b></div>
          <div><span>Available</span><b>{esc(latest)}</b></div>
          <div><span>Verification</span><b>{esc(verification)}</b></div>
          <div><span>Status</span><b data-update-phase>{esc(status.get("phase", "Not installed"))}</b></div>
        </div>
        <p data-update-error role="status">{esc(status.get("error"))}</p>
        <form method="post" action="/admin/updates" class="form-grid">
          <input type="hidden" name="csrf_token" value="{esc(csrf)}"><input type="hidden" name="action" value="configure">
          <label>Channel<select name="channel"{disabled}>{options([("release","Release"),("preview","Preview")], settings["channel"])}</select></label>
          <label>Installation<select name="mode"{disabled}>{options([("notify","Notify only"),("automatic","Automatic compatible updates")], settings["mode"])}</select></label>
          <label>Maintenance hour (one-hour window)<input name="hour" type="number" min="0" max="23" value="{settings["hour"]}"{disabled}></label>
          <label>Maintenance timezone<input name="timezone" value="{esc(settings["timezone"])}" required{disabled}></label>
          <button class="primary-button"{disabled}>Save update settings</button>
        </form>
        <div class="actions">{action("check", "Check now")}{action("postpone", "Postpone 24 hours")}
          {action("install", "Install reviewed build", candidate["digest"] if candidate else "", not candidate or candidate.get("image") == current_image)}
          {action("rollback", "Roll back previous image", previous["digest"] if previous else "", not previous)}
          {action("recover", "Retry recovery", blocked=status.get("phase") != "recovery_failed")}
        </div>
        {f'<p><a class="text-link" href="https://github.com/StealthCat/blockinator-web/commit/{esc(candidate["sha"])}" rel="noreferrer">View candidate changes</a></p>' if candidate else ""}
        {'<p class="panel-help">The rolled-back build is excluded from automatic installation. A different build or a manual reinstall is required.</p>' if status.get("blocked_digest") else ""}
        <p class="panel-help">Automatic updates require a compatible schema and major version. Channel changes may require a manual installation. Image rollback preserves current data and is available only for matching schema versions.</p>
        <p class="panel-help"><a class="text-link" href="https://github.com/StealthCat/blockinator-web/blob/fixes/updater/README.md" rel="noreferrer">Host setup and recovery instructions</a></p>
      </section>
      <section class="panel"><div class="panel-head"><h3>Update history</h3></div><div class="table-wrap"><table><thead><tr><th>UTC time</th><th>Version</th><th>Result</th><th>Details</th></tr></thead><tbody>{history or '<tr><td colspan="4" class="empty">No updates installed yet.</td></tr>'}</tbody></table></div></section>
    </section>'''
