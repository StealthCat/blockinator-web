(function () {
  function initializeFormRecovery() {
    document.querySelectorAll('form[method="post"]').forEach(function (form) {
      var action = new URL(form.action, window.location.href).pathname;
      if (!/^\/admin\/(lists|scopes|settings|query-domain)(\/|$)/.test(action) || /\/(delete|toggle)$/.test(action)) return;
      var busy = false;
      form.addEventListener('submit', function (event) {
        if (event.defaultPrevented) return;
        event.preventDefault();
        if (busy) return;
        busy = true;
        // Build the payload before disabling the submitter; its action chooses
        // Save vs Refresh. Keep the original DOM (including files) on errors.
        var data = new FormData(form);
        var submitter = event.submitter;
        if (submitter && submitter.name) data.append(submitter.name, submitter.value);
        var buttons = Array.from(form.querySelectorAll('button[type="submit"], button:not([type])'));
        var previous = buttons.map(function (button) { return button.disabled; });
        buttons.forEach(function (button) { button.disabled = true; });
        var message = form.querySelector('[data-form-message]');
        if (!message) {
          message = document.createElement('div');
          message.setAttribute('data-form-message', '');
          message.setAttribute('role', 'alert');
          message.className = 'flash full';
          form.prepend(message);
        }
        message.textContent = 'Saving…';
        fetch(form.action, {method: 'POST', credentials: 'same-origin', body: data, headers: {'Accept': 'text/html'}})
          .then(async function (response) {
            var url = new URL(response.url);
            if (url.pathname === '/login') { window.location.assign(url.href); return; }
            var error = url.searchParams.get('error');
            if (error) throw new Error(error);
            if (!response.ok) {
              var detail = 'Save failed. Your entries are still here; review them and retry.';
              if ((response.headers.get('content-type') || '').includes('application/json')) {
                var payload = await response.json();
                if (typeof payload.detail === 'string') detail = payload.detail;
              }
              throw new Error(detail);
            }
            // Successful handlers redirect to their canonical GET page.
            window.location.assign(response.redirected ? url.href : window.location.href);
          }).catch(function (error) {
            message.classList.add('bad');
            message.textContent = error.message + ' Your entries have been preserved.';
            message.scrollIntoView({block: 'nearest', behavior: 'smooth'});
          }).finally(function () {
            busy = false;
            buttons.forEach(function (button, index) { button.disabled = previous[index]; });
          });
      });
    });
  }
  function openHashDetails() {
    if (!window.location.hash) return;
    var target = document.getElementById(window.location.hash.slice(1));
    if (target && target.tagName === "DETAILS") {
      target.open = true;
      window.requestAnimationFrame(function () {
        target.scrollIntoView({ behavior: "smooth", block: "nearest" });
      });
    }
  }

  function syncGlobalAssignmentControls(form) {
    var toggle = form.querySelector("[data-global-toggle]");
    var group = form.querySelector("[data-scope-assignments]");
    if (!toggle || !group) return;

    var disabled = toggle.checked;
    group.classList.toggle("is-global-disabled", disabled);

    group.querySelectorAll('input[type="checkbox"][name="scope_id"]').forEach(function (checkbox) {
      checkbox.disabled = disabled;
      var option = checkbox.closest(".scope-option");
      if (option) option.classList.toggle("global-disabled", disabled);
    });
  }

  function initializeGlobalAssignmentControls() {
    document.querySelectorAll("form").forEach(function (form) {
      if (!form.querySelector("[data-global-toggle]")) return;
      syncGlobalAssignmentControls(form);
      form.querySelector("[data-global-toggle]").addEventListener("change", function () {
        syncGlobalAssignmentControls(form);
      });
    });
  }

  function syncScheduleControls(editor) {
    var toggle = editor.querySelector("[data-schedule-toggle]");
    var controls = editor.querySelector("[data-schedule-controls]");
    if (!toggle || !controls) return;
    controls.hidden = !toggle.checked;
    controls.classList.toggle("schedule-disabled", !toggle.checked);
    var windows = Array.from(editor.querySelectorAll("[data-schedule-window]"));
    var zone = editor.querySelector('[name="schedule_timezone"]').value.trim();
    var summaries = windows.map(function (window, index) {
      window.querySelector('[data-window-number]').textContent = index + 1;
      var days = Array.from(window.querySelectorAll('input[type="checkbox"]:checked'));
      var times = window.querySelectorAll('input[type="time"]');
      var start = times[0].value, end = times[1].value;
      if (!days.length) return "Window " + (index + 1) + ": select at least one day";
      return days.map(function (input) { return input.nextElementSibling.textContent; }).join(", ") +
        " · " + (start === end ? "All day" : start + "–" + end + (end < start ? " (overnight)" : ""));
    });
    editor.querySelector('[data-schedule-status]').textContent = !toggle.checked
      ? "Always active. No time restriction." : summaries.join(" OR ") + " · " + zone;
    editor.querySelector('[data-add-schedule-window]').disabled = windows.length >= 32;
    controls.setAttribute("aria-disabled", toggle.checked ? "false" : "true");
  }

  function initializeScheduleControls() {
    document.querySelectorAll("[data-schedule-editor]").forEach(function (editor) {
      var windows = editor.querySelector('[data-schedule-windows]');
      var nextId = Math.max.apply(null, Array.from(windows.children).map(function (row) {
        return Number(row.getAttribute('data-schedule-window'));
      })) + 1;
      syncScheduleControls(editor);
      editor.addEventListener("change", function () { syncScheduleControls(editor); });
      editor.addEventListener("click", function (event) {
        var button = event.target.closest('button');
        if (!button || !editor.contains(button)) return;
        if (button.hasAttribute('data-add-schedule-window')) {
          if (windows.children.length >= 32) return;
          var row = windows.firstElementChild.cloneNode(true);
          var index = nextId++;
          row.setAttribute('data-schedule-window', index);
          row.querySelectorAll('input').forEach(function (input) {
            input.name = input.name + '_' + index;
            if (input.type === 'checkbox') input.checked = true;
            if (input.type === 'time') input.value = '00:00';
          });
          var marker = document.createElement('input');
          marker.type = 'hidden'; marker.name = 'schedule_window'; marker.value = index;
          row.prepend(marker);
          var remove = document.createElement('button');
          remove.type = 'button'; remove.className = 'small-button danger';
          remove.setAttribute('data-remove-schedule-window', ''); remove.textContent = 'Remove window';
          row.querySelector('.schedule-window-head').appendChild(remove);
          windows.appendChild(row);
          syncScheduleControls(editor);
          row.querySelector('input[type="checkbox"]').focus();
        } else if (button.hasAttribute('data-remove-schedule-window')) {
          button.closest('[data-schedule-window]').remove();
          syncScheduleControls(editor);
          editor.querySelector('[data-add-schedule-window]').focus();
        } else if (button.hasAttribute('data-schedule-days')) {
          var selected = button.getAttribute('data-schedule-days').split(',');
          button.closest('[data-schedule-window]').querySelectorAll('input[type="checkbox"]').forEach(function (input) {
            input.checked = selected.indexOf(input.value) !== -1;
          });
          syncScheduleControls(editor);
        }
      });
    });
  }

  function syncScopeKindFields(form) {
    var select = form.querySelector("[data-scope-kind-select]");
    var networkFields = form.querySelector("[data-scope-network-fields]");
    var singleTarget = form.querySelector("[data-scope-single-target]");
    if (!select || !networkFields || !singleTarget) return;

    var whitelist = form.querySelector("[data-scope-whitelist]");
    var assignments = form.querySelector("[data-scope-list-assignments]");
    if (whitelist && assignments) {
      // Keep inputs enabled so hidden assignments survive saving and can be
      // restored when whitelisting is turned off.
      assignments.hidden = whitelist.querySelector("input").checked;
    }
    var isWhitelist = !!(whitelist && whitelist.querySelector("input").checked);
    // Preserve the stored blocking state; it only applies to blocklist targets.
    var blockingState = form.querySelector("[data-scope-blocking-state]");
    if (blockingState) blockingState.hidden = isWhitelist;
    var scheduleTitle = form.querySelector("[data-scope-schedule-title]");
    if (scheduleTitle) scheduleTitle.textContent = (isWhitelist ? "Whitelist" : "Blocklist") + " target schedule";
    var scheduleHelp = form.querySelector("[data-scope-schedule-help]");
    if (scheduleHelp) scheduleHelp.textContent = isWhitelist
      ? "Choose when this target allows all domains. Outside the schedule, other matching targets and the default policy apply."
      : "Choose when this target applies its blocklists and assigned whitelists.";
    var addButton = form.querySelector("[data-scope-add-button]");
    if (addButton) addButton.textContent = isWhitelist ? "Add whitelist target" : "Add blocklist target";
    var isNetwork = select.value === "network";
    networkFields.hidden = !isNetwork;
    singleTarget.hidden = isNetwork;

    networkFields.querySelectorAll("input").forEach(function (input) {
      input.disabled = !isNetwork;
    });
    singleTarget.querySelectorAll("input").forEach(function (input) {
      input.disabled = isNetwork;
    });
  }

  function initializeScopeKindFields() {
    document.querySelectorAll("form").forEach(function (form) {
      var select = form.querySelector("[data-scope-kind-select]");
      if (!select) return;
      syncScopeKindFields(form);
      form.addEventListener("change", function () {
        syncScopeKindFields(form);
      });
    });
  }

  function syncTlsSettings(form) {
    var select = form.querySelector("[data-tls-mode-select]");
    if (!select) return;

    var mode = select.value;
    var descriptions = {
      http: "Use Blockinator over HTTP only. No certificate or ACME configuration is required.",
      upload: "Use a certificate and private key you provide. Blockinator validates them before Caddy reloads.",
      acme: "Let Caddy obtain and renew the certificate automatically from Let's Encrypt or a custom ACME server."
    };

    form.querySelectorAll("[data-tls-mode-fields]").forEach(function (fieldset) {
      var active = fieldset.getAttribute("data-tls-mode-fields") === mode;
      fieldset.hidden = !active;
      fieldset.disabled = !active;
    });

    var description = form.querySelector("[data-tls-mode-description]");
    if (description) {
      description.textContent = descriptions[mode] || descriptions.http;
    }
  }

  function initializeTlsSettings() {
    document.querySelectorAll("[data-tls-settings-form]").forEach(function (form) {
      var select = form.querySelector("[data-tls-mode-select]");
      if (!select) return;
      syncTlsSettings(form);
      select.addEventListener("change", function () {
        syncTlsSettings(form);
      });
    });
  }

  function activateSettingsTab(root, name, updateHash) {
    var buttons = Array.prototype.slice.call(root.querySelectorAll("[data-settings-tab]"));
    var panels = Array.prototype.slice.call(root.querySelectorAll("[data-settings-panel]"));
    var valid = buttons.some(function (button) {
      return button.getAttribute("data-settings-tab") === name;
    });
    if (!valid) name = "general";

    buttons.forEach(function (button) {
      var active = button.getAttribute("data-settings-tab") === name;
      button.classList.toggle("active", active);
      button.setAttribute("aria-selected", active ? "true" : "false");
      button.tabIndex = active ? 0 : -1;
    });

    panels.forEach(function (panel) {
      panel.hidden = panel.getAttribute("data-settings-panel") !== name;
    });

    if (updateHash && window.location.hash !== "#" + name) {
      window.history.replaceState(null, "", window.location.pathname + window.location.search + "#" + name);
    }
  }

  function initializeSettingsTabs() {
    document.querySelectorAll("[data-settings-tabs]").forEach(function (root) {
      var initial = window.location.hash ? window.location.hash.slice(1) : "general";
      activateSettingsTab(root, initial, false);

      root.querySelectorAll("[data-settings-tab]").forEach(function (button) {
        button.addEventListener("click", function () {
          activateSettingsTab(root, button.getAttribute("data-settings-tab"), true);
        });
        button.addEventListener("keydown", function (event) {
          if (!["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Home", "End"].includes(event.key)) return;
          event.preventDefault();
          var buttons = Array.prototype.slice.call(root.querySelectorAll("[data-settings-tab]"));
          var index = buttons.indexOf(button);
          var delta = (event.key === "ArrowRight" || event.key === "ArrowDown") ? 1 : -1;
          if (event.key === "Home") index = -1, delta = 1;
          if (event.key === "End") index = 0, delta = -1;
          var next = buttons[(index + delta + buttons.length) % buttons.length];
          next.focus();
          activateSettingsTab(root, next.getAttribute("data-settings-tab"), true);
        });
      });
    });

    window.addEventListener("hashchange", function () {
      document.querySelectorAll("[data-settings-tabs]").forEach(function (root) {
        activateSettingsTab(root, window.location.hash.slice(1), false);
      });
    });
  }

  function initializeListEditNavigation() {
    var nav = document.querySelector(".list-edit-section-nav");
    if (!nav) return;

    var links = Array.prototype.slice.call(nav.querySelectorAll('a[href^="#"]'));
    if (!links.length) return;

    function activate(hash) {
      links.forEach(function (link) {
        link.classList.toggle("active", link.getAttribute("href") === hash);
      });
    }

    links.forEach(function (link) {
      link.addEventListener("click", function () {
        activate(link.getAttribute("href"));
      });
    });

    if (window.location.hash && links.some(function (link) {
      return link.getAttribute("href") === window.location.hash;
    })) {
      activate(window.location.hash);
    }

    window.addEventListener("hashchange", function () {
      if (window.location.hash) activate(window.location.hash);
    });
  }

  function initializeNavigation() {
    var toggle = document.querySelector("[data-navigation-toggle]");
    var sidebar = document.getElementById("app-navigation");
    if (!toggle || !sidebar) return;
    document.documentElement.classList.add("js-navigation");
    function setOpen(open) {
      sidebar.classList.toggle("is-open", open);
      toggle.setAttribute("aria-expanded", String(open));
    }
    toggle.addEventListener("click", function () {
      var open = toggle.getAttribute("aria-expanded") !== "true";
      setOpen(open);
      if (open) sidebar.querySelector("a").focus();
    });
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && toggle.getAttribute("aria-expanded") === "true") {
        setOpen(false);
        toggle.focus();
      }
    });
  }

  function initializeTableDensity() {
    var control = document.querySelector("select[data-table-density]");
    var density = "comfortable";
    try { density = localStorage.getItem("blockinator-table-density") || density; } catch (_) {}
    if (density !== "compact") density = "comfortable";
    document.documentElement.setAttribute("data-table-density", density);
    if (!control) return;
    control.value = density;
    control.addEventListener("change", function () {
      document.documentElement.setAttribute("data-table-density", control.value);
      try { localStorage.setItem("blockinator-table-density", control.value); } catch (_) {}
    });
  }

  function initializeQueryLogRefresh() {
    var panel = document.querySelector("[data-query-log-refresh]");
    if (!panel) return;
    var seconds = parseInt(panel.getAttribute("data-query-log-refresh") || "0", 10);
    var status = panel.querySelector("[data-query-refresh-status]");
    if (panel.getAttribute("data-query-snapshot") === "1") {
      if (status) status.textContent = "Browsing a snapshot · select Latest results to resume live updates";
      return;
    }
    if (!Number.isFinite(seconds) || seconds <= 0) {
      if (status) status.textContent = "Auto refresh off";
      return;
    }
    var timer = null;
    var controller = null;
    var stopped = false;
    var dirty = false;
    var filters = panel.querySelector(".query-filter-bar");
    // Do not replace data while filters have unsubmitted edits or a row is being inspected.
    filters.addEventListener("input", function () { dirty = true; });
    filters.addEventListener("change", function () { dirty = true; });
    function schedule() {
      if (stopped) return;
      if (timer !== null) window.clearTimeout(timer);
      timer = window.setTimeout(refresh, seconds * 1000);
    }
    function interacting() {
      return dirty || panel.querySelector("details[open]") ||
        (panel.contains(document.activeElement) && document.activeElement !== document.body);
    }
    function refresh() {
      if (document.hidden || interacting()) {
        if (status) status.textContent = dirty ? "Apply filters to resume live updates" : "Live updates paused while viewing";
        schedule();
        return;
      }
      controller = new AbortController();
      var timeout = window.setTimeout(function () { controller.abort(); }, 15000);
      fetch("/queries/rows" + window.location.search, { credentials: "same-origin", cache: "no-store", signal: controller.signal,
        headers: { "Accept": "text/html" } }).then(function (response) {
        if (response.redirected && new URL(response.url).pathname === "/login") {
          stopped = true;
          throw new Error("session");
        }
        if (!response.ok) throw new Error("refresh");
        return response.text();
      }).then(function (html) {
        var incoming = new DOMParser().parseFromString(html, "text/html");
        var next = incoming.querySelector(".query-table tbody");
        if (!next) throw new Error("refresh");
        // A user may have started editing after this request began.
        if (interacting() || document.hidden || stopped) return;
        var wrap = panel.querySelector(".table-wrap");
        var scrollLeft = wrap.scrollLeft;
        var x = window.scrollX, y = window.scrollY;
        panel.querySelector(".query-table tbody").replaceWith(next);
        wrap.scrollLeft = scrollLeft;
        window.scrollTo(x, y);
        var pagination = incoming.querySelector(".query-pagination");
        if (pagination) panel.querySelector(".query-pagination").replaceWith(pagination);
        var count = incoming.querySelector(".result-count");
        if (count) panel.querySelector(".result-count").textContent = count.textContent;
        var description = incoming.querySelector(".query-head p");
        if (description) panel.querySelector(".query-head p").textContent = description.textContent;
        if (status) status.textContent = "Updated just now · refreshes every " + seconds + "s";
      }).catch(function (error) {
        if (status) status.textContent = error.message === "session"
          ? "Session expired. Reload to sign in." : "Refresh unavailable. Retrying automatically.";
      }).finally(function () {
        window.clearTimeout(timeout);
        controller = null;
        schedule();
      });
    }
    if (status) status.textContent = "Refreshes every " + seconds + "s";
    schedule();
    window.addEventListener("pagehide", function () {
      stopped = true;
      window.clearTimeout(timer);
      if (controller) controller.abort();
    });
    window.addEventListener("pageshow", function (event) {
      if (event.persisted) { stopped = false; schedule(); }
    });
  }

  function statisticsNumber(value) {
    var numeric = Number(value || 0);
    return numeric.toLocaleString();
  }

  function statisticsResponseTime(value) {
    if (value === null || value === undefined || !Number.isFinite(Number(value))) return "—";
    var milliseconds = Number(value);
    if (milliseconds < 1) return milliseconds.toFixed(3) + " ms";
    if (milliseconds < 100) return milliseconds.toFixed(2) + " ms";
    return milliseconds.toFixed(1) + " ms";
  }

  function statisticsSvgElement(name, attributes, text) {
    var element = document.createElementNS("http://www.w3.org/2000/svg", name);
    Object.keys(attributes || {}).forEach(function (key) {
      element.setAttribute(key, String(attributes[key]));
    });
    if (text !== undefined) element.textContent = text;
    return element;
  }

  function statisticsPath(points, valueKey, left, top, width, height, maxY) {
    if (!points.length) return "";
    return points.map(function (point, index) {
      var x = points.length === 1
        ? left + width / 2
        : left + (index / (points.length - 1)) * width;
      var value = Number(point[valueKey] || 0);
      var y = top + height - (value / maxY) * height;
      return (index === 0 ? "M" : "L") + x.toFixed(2) + " " + y.toFixed(2);
    }).join(" ");
  }

  function statisticsNullablePath(points, valueKey, left, top, width, height, maxY) {
    var commands = [];
    var activeSegment = false;

    points.forEach(function (point, index) {
      var rawValue = point[valueKey];
      var value = Number(rawValue);
      if (rawValue === null || rawValue === undefined || !Number.isFinite(value)) {
        activeSegment = false;
        return;
      }

      var x = points.length === 1
        ? left + width / 2
        : left + (index / (points.length - 1)) * width;
      var y = top + height - (value / maxY) * height;
      commands.push(
        (activeSegment ? "L" : "M") + x.toFixed(2) + " " + y.toFixed(2)
      );
      activeSegment = true;
    });

    return commands.join(" ");
  }

  function statisticsResponseTickStep(maxValue) {
    if (!Number.isFinite(maxValue) || maxValue <= 0) return 1;
    var rawStep = maxValue / 4;
    var magnitude = Math.pow(10, Math.floor(Math.log10(rawStep)));
    var normalized = rawStep / magnitude;
    var nice = normalized <= 1 ? 1 : normalized <= 2 ? 2 : normalized <= 5 ? 5 : 10;
    return nice * magnitude;
  }

  function statisticsResponseAxisLabel(value) {
    if (value === 0) return "0 ms";
    if (value < 1) return value.toFixed(2) + " ms";
    if (value < 10) return value.toFixed(1) + " ms";
    if (value < 100) return value.toFixed(0) + " ms";
    return Math.round(value).toLocaleString() + " ms";
  }

  function renderStatisticsChart(root, payload) {
    var svg = root.querySelector("[data-statistics-chart]");
    if (!svg) return;

    var points = Array.isArray(payload.points) ? payload.points : [];
    var left = 62;
    var right = 68;
    var top = 18;
    var bottom = 42;
    var fullWidth = Math.max(240, Math.round(svg.getBoundingClientRect().width));
    svg.setAttribute("viewBox", "0 0 " + fullWidth + " 340");
    var fullHeight = 340;
    var width = fullWidth - left - right;
    var height = fullHeight - top - bottom;
    var maxValue = 0;
    var maxResponseTime = 0;

    points.forEach(function (point) {
      maxValue = Math.max(maxValue, Number(point.queries || 0), Number(point.blocks || 0));
      var responseTime = Number(point.average_response_time_ms);
      if (
        point.average_response_time_ms !== null
        && point.average_response_time_ms !== undefined
        && Number.isFinite(responseTime)
      ) {
        maxResponseTime = Math.max(maxResponseTime, responseTime);
      }
    });
    var step = Math.max(1, Math.ceil(maxValue / 4));
    var maxY = step * 4;
    var responseStep = statisticsResponseTickStep(maxResponseTime);
    var responseMaxY = responseStep * 4;

    svg.textContent = "";

    for (var tick = 0; tick <= 4; tick += 1) {
      var value = step * tick;
      var y = top + height - (tick / 4) * height;
      svg.appendChild(statisticsSvgElement("line", {
        x1: left,
        y1: y,
        x2: left + width,
        y2: y,
        "class": "statistics-grid-line"
      }));
      svg.appendChild(statisticsSvgElement("text", {
        x: left - 12,
        y: y + 4,
        "text-anchor": "end",
        "class": "statistics-axis-label"
      }, Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(value)));
      svg.appendChild(statisticsSvgElement("text", {
        x: left + width + 12,
        y: y + 4,
        "text-anchor": "start",
        "class": "statistics-axis-label statistics-axis-response"
      }, statisticsResponseAxisLabel(responseStep * tick)));
    }

    var labelIndexes = [];
    if (points.length) {
      var labelCount = Math.min(Math.max(2, Math.floor(width / 90)), 6, points.length);
      for (var labelIndex = 0; labelIndex < labelCount; labelIndex += 1) {
        labelIndexes.push(Math.round(labelIndex * (points.length - 1) / Math.max(1, labelCount - 1)));
      }
    }
    labelIndexes.filter(function (value, index, array) {
      return array.indexOf(value) === index;
    }).forEach(function (index) {
      var point = points[index];
      var x = points.length === 1
        ? left + width / 2
        : left + (index / (points.length - 1)) * width;
      svg.appendChild(statisticsSvgElement("text", {
        x: x,
        y: fullHeight - 13,
        "text-anchor": index === 0 ? "start" : index === points.length - 1 ? "end" : "middle",
        "class": "statistics-axis-label statistics-axis-time"
      }, point.label || ""));
    });

    if (points.length) {
      var queryPath = statisticsPath(points, "queries", left, top, width, height, maxY);
      var blockPath = statisticsPath(points, "blocks", left, top, width, height, maxY);
      var responsePath = statisticsNullablePath(
        points,
        "average_response_time_ms",
        left,
        top,
        width,
        height,
        responseMaxY
      );
      var baseline = top + height;
      var firstX = points.length === 1 ? left + width / 2 : left;
      var lastX = points.length === 1 ? left + width / 2 : left + width;

      if (queryPath) {
        svg.appendChild(statisticsSvgElement("path", {
          d: queryPath + " L" + lastX + " " + baseline + " L" + firstX + " " + baseline + " Z",
          "class": "statistics-area statistics-area-queries"
        }));
        svg.appendChild(statisticsSvgElement("path", {
          d: queryPath,
          "class": "statistics-series statistics-series-queries"
        }));
      }
      if (blockPath) {
        svg.appendChild(statisticsSvgElement("path", {
          d: blockPath,
          "class": "statistics-series statistics-series-blocks"
        }));
      }
      if (responsePath) {
        svg.appendChild(statisticsSvgElement("path", {
          d: responsePath,
          "class": "statistics-series statistics-series-response"
        }));
      }
    }

    var empty = root.querySelector("[data-statistics-empty]");
    if (empty) {
      var hasActivity = points.some(function (point) {
        return Number(point.queries || 0) > 0;
      });
      empty.hidden = hasActivity;
    }
  }

  function initializeStatisticsDashboard() {
    var root = document.querySelector("[data-statistics-dashboard]");
    if (!root) return;

    var timer = null;
    var loading = false;
    var controller = null;
    var requestVersion = 0;
    var lastPayload = null;
    var windowMinutes = parseInt(root.getAttribute("data-window") || "60", 10);

    function updateTotals(payload) {
      var totals = payload.totals || {};
      var queries = root.querySelector('[data-statistics-total="queries"]');
      var blocks = root.querySelector('[data-statistics-total="blocks"]');
      var response = root.querySelector('[data-statistics-total="response"]');
      var bucket = root.querySelector("[data-statistics-bucket]");
      var updated = root.querySelector("[data-statistics-updated]");

      if (queries) queries.textContent = statisticsNumber(totals.queries);
      if (blocks) blocks.textContent = statisticsNumber(totals.blocks);
      if (response) response.textContent = statisticsResponseTime(totals.average_response_time_ms);
      if (bucket) {
        var bucketMinutes = Number(payload.bucket_minutes || 1);
        bucket.textContent = bucketMinutes + " minute" + (bucketMinutes === 1 ? "" : "s") + " per interval";
      }
      if (updated) {
        updated.textContent = "Live · updated just now · " + (payload.timezone || "UTC");
        updated.classList.remove("error");
      }
    }

    function load() {
      if (loading || document.hidden) return;
      loading = true;
      var version = ++requestVersion;
      controller = new AbortController();
      var currentController = controller;
      var timeout = window.setTimeout(function () { currentController.abort(); }, 15000);

      fetch("/api/v1/statistics?minutes=" + encodeURIComponent(windowMinutes), {
        method: "GET",
        credentials: "same-origin",
        signal: controller.signal,
        headers: { "Accept": "application/json" }
      }).then(function (response) {
        if (!response.ok) throw new Error("Statistics request failed");
        return response.json();
      }).then(function (payload) {
        if (version !== requestVersion) return;
        lastPayload = payload;
        updateTotals(payload);
        renderStatisticsChart(root, payload);
      }).catch(function () {
        if (version !== requestVersion) return;
        var updated = root.querySelector("[data-statistics-updated]");
        if (updated) {
          updated.textContent = "Live data temporarily unavailable";
          updated.classList.add("error");
        }
      }).finally(function () {
        window.clearTimeout(timeout);
        if (version === requestVersion) loading = false;
      });
    }

    root.querySelectorAll("[data-statistics-window]").forEach(function (button) {
      button.addEventListener("click", function () {
        windowMinutes = parseInt(button.getAttribute("data-statistics-window") || "60", 10);
        root.setAttribute("data-window", String(windowMinutes));
        root.querySelectorAll("[data-statistics-window]").forEach(function (candidate) {
          candidate.classList.toggle("active", candidate === button);
        });
        if (controller) controller.abort();
        requestVersion += 1;
        loading = false;
        load();
      });
    });

    document.addEventListener("visibilitychange", function () {
      if (!document.hidden) load();
    });

    var resizeObserver = null;
    if (window.ResizeObserver) {
      var lastWidth = 0;
      resizeObserver = new ResizeObserver(function (entries) {
        var width = Math.round(entries[0].contentRect.width);
        if (width !== lastWidth && lastPayload) renderStatisticsChart(root, lastPayload);
        lastWidth = width;
      });
      resizeObserver.observe(root.querySelector("[data-statistics-chart]"));
    }
    load();
    timer = window.setInterval(load, 5000);
    window.addEventListener("pagehide", function () {
      if (controller) controller.abort();
      requestVersion += 1;
      loading = false;
      if (timer !== null) window.clearInterval(timer);
      timer = null;
      if (resizeObserver) resizeObserver.disconnect();
    });
    window.addEventListener("pageshow", function () {
      if (timer === null) timer = window.setInterval(load, 5000);
      if (resizeObserver) resizeObserver.observe(root.querySelector("[data-statistics-chart]"));
      load();
    });
  }

  window.addEventListener("hashchange", openHashDetails);
  openHashDetails();
  initializeFormRecovery();
  initializeGlobalAssignmentControls();
  initializeScheduleControls();
  initializeScopeKindFields();
  initializeTlsSettings();
  initializeSettingsTabs();
  initializeListEditNavigation();
  initializeNavigation();
  initializeTableDensity();
  initializeQueryLogRefresh();
  initializeStatisticsDashboard();
})();
