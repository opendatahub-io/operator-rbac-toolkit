document.addEventListener("DOMContentLoaded", function () {
  var overlay = document.createElement("div");
  overlay.className = "diagram-overlay";
  overlay.setAttribute("role", "dialog");
  overlay.setAttribute("aria-modal", "true");
  overlay.setAttribute("aria-label", "Diagram zoom viewer");
  overlay.innerHTML =
    '<div class="diagram-overlay-controls">' +
    '<button class="diagram-btn" id="diagram-zoom-in" title="Zoom in" aria-label="Zoom in">+</button>' +
    '<button class="diagram-btn" id="diagram-zoom-out" title="Zoom out" aria-label="Zoom out">−</button>' +
    '<button class="diagram-btn" id="diagram-zoom-reset" title="Reset zoom" aria-label="Reset zoom">1:1</button>' +
    '<button class="diagram-btn" id="diagram-close" title="Close" aria-label="Close diagram viewer">✕</button>' +
    "</div>" +
    '<div class="diagram-overlay-content"></div>';
  document.body.appendChild(overlay);

  var content = overlay.querySelector(".diagram-overlay-content");
  var closeBtn = overlay.querySelector("#diagram-close");
  var scale = 1;
  var triggerElement = null;

  function openDiagram(svg) {
    triggerElement = svg;
    var clone = svg.cloneNode(true);
    clone.removeAttribute("style");
    clone.style.maxWidth = "100%";
    clone.style.maxHeight = "100%";
    content.innerHTML = "";
    content.appendChild(clone);
    scale = 1;
    applyScale();
    overlay.classList.add("active");
    document.body.style.overflow = "hidden";
    closeBtn.focus();
  }

  function closeDiagram() {
    overlay.classList.remove("active");
    document.body.style.overflow = "";
    content.innerHTML = "";
    scale = 1;
    if (triggerElement) {
      triggerElement.focus();
      triggerElement = null;
    }
  }

  function applyScale() {
    var svg = content.querySelector("svg");
    if (svg) {
      svg.style.transform = "scale(" + scale + ")";
      svg.style.transformOrigin = "center center";
    }
  }

  overlay.querySelector("#diagram-zoom-in").addEventListener("click", function () {
    scale = Math.min(scale * 1.25, 5);
    applyScale();
  });

  overlay.querySelector("#diagram-zoom-out").addEventListener("click", function () {
    scale = Math.max(scale / 1.25, 0.2);
    applyScale();
  });

  overlay.querySelector("#diagram-zoom-reset").addEventListener("click", function () {
    scale = 1;
    applyScale();
  });

  overlay.querySelector("#diagram-close").addEventListener("click", closeDiagram);

  overlay.addEventListener("click", function (e) {
    if (e.target === overlay || e.target === content) {
      closeDiagram();
    }
  });

  document.addEventListener("keydown", function (e) {
    if (!overlay.classList.contains("active")) return;
    if (e.key === "Escape") closeDiagram();
    if (e.key === "+" || e.key === "=") {
      scale = Math.min(scale * 1.25, 5);
      applyScale();
    }
    if (e.key === "-") {
      scale = Math.max(scale / 1.25, 0.2);
      applyScale();
    }
    if (e.key === "0") {
      scale = 1;
      applyScale();
    }
  });

  var observer = new MutationObserver(function () {
    document.querySelectorAll("pre.mermaid svg, .mermaid svg").forEach(function (svg) {
      if (svg.dataset.zoomEnabled) return;
      svg.dataset.zoomEnabled = "true";
      svg.style.cursor = "pointer";

      var hint = document.createElement("div");
      hint.className = "diagram-hint";
      hint.textContent = "Click to expand";
      svg.parentElement.style.position = "relative";
      svg.parentElement.appendChild(hint);

      svg.addEventListener("click", function () {
        openDiagram(svg);
      });
    });
  });

  observer.observe(document.body, { childList: true, subtree: true });
});
