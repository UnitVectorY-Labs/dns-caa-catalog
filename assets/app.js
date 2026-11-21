// dns-caa-catalog interactive filtering, HTMX synchronization and copy helpers.
(function () {
  function applyFilters() {
    const searchInput = document.getElementById("searchInput");
    const hideMissingCaa = document.getElementById("hideMissingCaa");
    const links = document.querySelectorAll("#domain-list a.caa-domain-link");
    if (!links.length) return;

    const filter = searchInput ? searchInput.value.trim().toLowerCase() : "";
    const hideNoCaa = hideMissingCaa ? hideMissingCaa.checked : false;

    const activeFilters = [];
    document
      .querySelectorAll("#sidebar input[data-filter]")
      .forEach((checkbox) => {
        if (checkbox.checked) {
          activeFilters.push(checkbox.getAttribute("data-filter"));
        }
      });

    let visibleCount = 0;
    links.forEach((link) => {
      const domain = (
        link.getAttribute("data-domain") || link.textContent || ""
      ).toLowerCase();
      const matchesSearch = !filter || domain.includes(filter);
      const hasCaa = link.getAttribute("data-has-caa") === "true";
      const showForCaa = !hideNoCaa || hasCaa;

      let matchesRecordFilter = true;
      for (let i = 0; i < activeFilters.length; i++) {
        if (link.getAttribute("data-has-" + activeFilters[i]) !== "true") {
          matchesRecordFilter = false;
          break;
        }
      }

      const visible = matchesSearch && showForCaa && matchesRecordFilter;
      link.hidden = !visible;
      if (visible) visibleCount++;
    });

    const countEl = document.getElementById("nav-count");
    if (countEl) {
      countEl.textContent =
        visibleCount.toLocaleString("en-US") +
        (visibleCount === 1 ? " domain" : " domains");
    }

    const emptyEl = document.getElementById("nav-empty");
    if (emptyEl) {
      emptyEl.hidden = visibleCount > 0;
    }
  }

  function syncActiveNav() {
    const path = window.location.pathname;
    const isHome = path === "/" || path === "/index.html" || path === "";

    const overviewLink = document.querySelector(
      '.site-header nav a[data-nav="overview"]',
    );
    if (overviewLink) {
      if (isHome) overviewLink.setAttribute("aria-current", "page");
      else overviewLink.removeAttribute("aria-current");
    }

    document.querySelectorAll("#domain-list a.caa-domain-link").forEach((a) => {
      if (a.getAttribute("href") === path) {
        a.setAttribute("aria-current", "page");
      } else {
        a.removeAttribute("aria-current");
      }
    });
  }

  function enhanceDynamicContent(container) {
    if (!container) return;

    container.querySelectorAll("[data-enable-with-js]").forEach((el) => {
      el.disabled = false;
    });
    container.querySelectorAll("[data-requires-js]").forEach((el) => {
      el.hidden = false;
    });

    const titleEl = container.querySelector("[data-page-title]");
    if (titleEl && titleEl.dataset.pageTitle) {
      document.title = titleEl.dataset.pageTitle;
    }

    // Bind copy buttons added via HTMX swaps (uvy.js binds initial-load ones).
    container
      .querySelectorAll("[data-copy-target], [data-copy-text]")
      .forEach((button) => {
        if (button.dataset.copyBound === "true") return;
        button.dataset.copyBound = "true";
        button.addEventListener("click", async function () {
          const targetId = button.dataset.copyTarget;
          const text = targetId
            ? (document.getElementById(targetId)?.textContent ?? "").trim()
            : button.dataset.copyText || "";
          if (!text) return;
          try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
              await navigator.clipboard.writeText(text);
            } else {
              const area = document.createElement("textarea");
              area.value = text;
              area.setAttribute("readonly", "");
              area.style.position = "fixed";
              area.style.opacity = "0";
              document.body.append(area);
              area.select();
              document.execCommand("copy");
              area.remove();
            }
          } catch (_) {}
          button.classList.add("is-copied");
          clearTimeout(button._copyTimer);
          button._copyTimer = setTimeout(() => {
            button.classList.remove("is-copied");
          }, 1800);
        });
      });

    initProviderFilter(container);
  }

  function initProviderFilter(scope) {
    const input = scope.querySelector("#provider-domain-filter");
    if (!input || input.dataset.bound === "true") return;
    input.dataset.bound = "true";

    const clearBtn = scope.querySelector("#provider-domain-clear");
    const countEl = scope.querySelector("#provider-domain-count");
    const rows = [...scope.querySelectorAll("tr[data-provider-domain]")];

    function applyProviderFilter() {
      const q = input.value.trim().toLowerCase();
      let shown = 0;
      rows.forEach((row) => {
        const domain = (row.dataset.providerDomain || "").toLowerCase();
        const match = !q || domain.includes(q);
        row.hidden = !match;
        if (match) shown++;
      });
      if (countEl) {
        countEl.textContent =
          shown.toLocaleString("en-US") +
          " of " +
          rows.length.toLocaleString("en-US") +
          " rows shown";
      }
      scope.querySelectorAll("[data-provider-panel]").forEach((panel) => {
        const panelRows = panel.querySelectorAll("tr[data-provider-domain]");
        let visibleInPanel = 0;
        panelRows.forEach((r) => {
          if (!r.hidden) visibleInPanel++;
        });
        const empty = panel.querySelector("[data-provider-empty]");
        if (empty) empty.hidden = visibleInPanel > 0;
      });
    }

    input.addEventListener("input", applyProviderFilter);
    if (clearBtn) {
      clearBtn.addEventListener("click", () => {
        input.value = "";
        applyProviderFilter();
        input.focus();
      });
    }
    applyProviderFilter();
  }

  function bindSidebarControls() {
    const searchInput = document.getElementById("searchInput");
    if (searchInput && searchInput.dataset.bound !== "true") {
      searchInput.dataset.bound = "true";
      searchInput.addEventListener("input", applyFilters);
    }
    document
      .querySelectorAll('#sidebar input[type="checkbox"]')
      .forEach((checkbox) => {
        if (checkbox.dataset.bound === "true") return;
        checkbox.dataset.bound = "true";
        checkbox.addEventListener("change", applyFilters);
      });
  }

  document.addEventListener("DOMContentLoaded", function () {
    // Mark copy buttons already bound by uvy.js so we never double-bind them.
    document
      .querySelectorAll("[data-copy-target], [data-copy-text]")
      .forEach((btn) => {
        btn.dataset.copyBound = "true";
      });

    bindSidebarControls();
    initProviderFilter(document);
    applyFilters();
    syncActiveNav();

    function handleSwap(event) {
      const target = event.target;
      if (!target) return;
      if (target.id === "domain-list" || target.closest?.("#sidebar")) {
        applyFilters();
        syncActiveNav();
      } else if (target.id === "content") {
        enhanceDynamicContent(target);
        syncActiveNav();
        window.scrollTo({ top: 0, behavior: "instant" });
      }
    }

    document.body.addEventListener("htmx:after:swap", handleSwap);
    document.body.addEventListener("htmx:afterSwap", handleSwap);
    window.addEventListener("popstate", syncActiveNav);
  });
})();
