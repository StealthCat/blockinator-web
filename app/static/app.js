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
    form.querySelectorAll("[data-tls-host-field]").forEach(function (node) {
      node.hidden = mode === "http";
    });
    form.querySelectorAll("[data-tls-upload-fields]").forEach(function (node) {
      node.hidden = mode !== "upload";
    });
    form.querySelectorAll("[data-tls-acme-fields]").forEach(function (node) {
      node.hidden = mode !== "acme";
    });
    form.querySelectorAll("[data-tls-http-behavior]").forEach(function (node) {
      node.hidden = mode === "http";
    });
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

  window.addEventListener("hashchange", openHashDetails);
  openHashDetails();
  initializeGlobalAssignmentControls();
  initializeScheduleControls();
  initializeScopeKindFields();
  initializeTlsSettings();
})();
