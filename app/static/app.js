(function () {
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
    controls.classList.toggle("schedule-disabled", !toggle.checked);
    controls.setAttribute("aria-disabled", toggle.checked ? "false" : "true");
    controls.querySelectorAll("input").forEach(function (input) {
      if (toggle.checked) {
        input.removeAttribute("tabindex");
      } else {
        input.setAttribute("tabindex", "-1");
      }
    });
  }

  function initializeScheduleControls() {
    document.querySelectorAll("[data-schedule-editor]").forEach(function (editor) {
      var toggle = editor.querySelector("[data-schedule-toggle]");
      if (!toggle) return;
      syncScheduleControls(editor);
      toggle.addEventListener("change", function () {
        syncScheduleControls(editor);
      });
    });
  }

  function syncScopeKindFields(form) {
    var select = form.querySelector("[data-scope-kind-select]");
    var networkFields = form.querySelector("[data-scope-network-fields]");
    var singleTarget = form.querySelector("[data-scope-single-target]");
    if (!select || !networkFields || !singleTarget) return;

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
      select.addEventListener("change", function () {
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
          if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
          var buttons = Array.prototype.slice.call(root.querySelectorAll("[data-settings-tab]"));
          var index = buttons.indexOf(button);
          var delta = event.key === "ArrowRight" ? 1 : -1;
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

  function initializeQueryLogRefresh() {
    var panel = document.querySelector("[data-query-log-refresh]");
    if (!panel) return;

    var seconds = parseInt(panel.getAttribute("data-query-log-refresh") || "0", 10);
    if (!Number.isFinite(seconds) || seconds <= 0) return;

    var timer = null;
    function schedule() {
      if (timer !== null) window.clearTimeout(timer);
      timer = window.setTimeout(function () {
        if (document.hidden) {
          schedule();
          return;
        }
        window.location.reload();
      }, seconds * 1000);
    }

    document.addEventListener("visibilitychange", function () {
      if (!document.hidden) schedule();
    });
    schedule();
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

  function renderStatisticsChart(root, payload) {
    var svg = root.querySelector("[data-statistics-chart]");
    if (!svg) return;

    var points = Array.isArray(payload.points) ? payload.points : [];
    var left = 56;
    var right = 24;
    var top = 18;
    var bottom = 42;
    var fullWidth = 1000;
    var fullHeight = 340;
    var width = fullWidth - left - right;
    var height = fullHeight - top - bottom;
    var maxValue = 0;

    points.forEach(function (point) {
      maxValue = Math.max(maxValue, Number(point.queries || 0), Number(point.blocks || 0));
    });
    var step = Math.max(1, Math.ceil(maxValue / 4));
    var maxY = step * 4;

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
      }, String(value)));
    }

    var labelIndexes = [];
    if (points.length) {
      var labelCount = Math.min(6, points.length);
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

      fetch("/api/v1/statistics?minutes=" + encodeURIComponent(windowMinutes), {
        method: "GET",
        credentials: "same-origin",
        headers: { "Accept": "application/json" }
      }).then(function (response) {
        if (!response.ok) throw new Error("Statistics request failed");
        return response.json();
      }).then(function (payload) {
        updateTotals(payload);
        renderStatisticsChart(root, payload);
      }).catch(function () {
        var updated = root.querySelector("[data-statistics-updated]");
        if (updated) {
          updated.textContent = "Live data temporarily unavailable";
          updated.classList.add("error");
        }
      }).finally(function () {
        loading = false;
      });
    }

    root.querySelectorAll("[data-statistics-window]").forEach(function (button) {
      button.addEventListener("click", function () {
        windowMinutes = parseInt(button.getAttribute("data-statistics-window") || "60", 10);
        root.setAttribute("data-window", String(windowMinutes));
        root.querySelectorAll("[data-statistics-window]").forEach(function (candidate) {
          candidate.classList.toggle("active", candidate === button);
        });
        load();
      });
    });

    document.addEventListener("visibilitychange", function () {
      if (!document.hidden) load();
    });

    load();
    timer = window.setInterval(load, 5000);
    window.addEventListener("pagehide", function () {
      if (timer !== null) window.clearInterval(timer);
    }, { once: true });
  }

  window.addEventListener("hashchange", openHashDetails);
  openHashDetails();
  initializeGlobalAssignmentControls();
  initializeScheduleControls();
  initializeScopeKindFields();
  initializeTlsSettings();
  initializeSettingsTabs();
  initializeQueryLogRefresh();
  initializeStatisticsDashboard();
})();
