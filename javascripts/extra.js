/**
 * Navigation folding: collapse all sections except the current page's section.
 * Runs on page load and after instant navigation.
 */
document.addEventListener("DOMContentLoaded", function () {
  // Wait a brief moment for navigation to render
  setTimeout(collapseInactiveSections, 200);
});

// Also run on instant navigation (Material's built-in SPA)
if (typeof document.addEventListener !== "undefined") {
  document.addEventListener("DOMContentSwitch", function () {
    setTimeout(collapseInactiveSections, 200);
  });
}

function collapseInactiveSections() {
  "use strict";

  var nav = document.querySelector(".md-nav--primary");
  if (!nav) return;

  // Find the currently active nav item (deepest level)
  var activeItem = nav.querySelector("li.md-nav__item--active");
  if (!activeItem) return;

  // Collect all section labels (top-level nav__item with label)
  var allLabels = nav.querySelectorAll(
    ":scope > .md-nav__list > .md-nav__item--section > .md-nav__link"
  );

  // Collect all parent labels (labels whose children contain activeItem)
  var activePath = [];
  var el = activeItem;
  while (el && el !== nav) {
    if (
      el.classList.contains("md-nav__item--section") ||
      el.classList.contains("md-nav__item")
    ) {
      // Check if this is a label (has an anchor/span that looks like a section)
      var link = el.querySelector(":scope > .md-nav__link");
      if (link) {
        activePath.unshift(el);
      }
    }
    el = el.parentElement ? el.parentElement.closest(".md-nav__item") : null;
  }

  // Collapse all labels not in active path
  allLabels.forEach(function (label) {
    var parent = label.parentElement;
    if (!parent) return;

    var toggle = label.querySelector(".md-nav__icon");
    var list = parent.querySelector(":scope > .md-nav__list");

    if (!list) return;

    // If this label is an ancestor of active page, keep expanded
    var shouldExpand = false;
    activePath.forEach(function (ap) {
      if (ap === parent || ap.contains(parent) || parent.contains(ap)) {
        shouldExpand = true;
      }
    });

    if (!shouldExpand) {
      // Collapse
      list.setAttribute("hidden", "");

      // Remove the "expanded" state from the toggle icon
      var toggleIcon = label.querySelector(".md-nav__icon");
      if (toggleIcon) {
        toggleIcon.style.transform = "";
      }
    }
  });
}
