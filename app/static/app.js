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

  window.addEventListener("hashchange", openHashDetails);
  openHashDetails();
  initializeGlobalAssignmentControls();
})();
