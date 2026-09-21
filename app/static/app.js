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

  window.addEventListener("hashchange", openHashDetails);
  openHashDetails();
})();
