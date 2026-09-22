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

  window.addEventListener("hashchange", openHashDetails);
  openHashDetails();
  initializeGlobalAssignmentControls();
  initializeScheduleControls();
  initializeScopeKindFields();
  initializeTlsSettings();
  initializeSettingsTabs();
  initializeQueryLogRefresh();
})();
