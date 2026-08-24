/*
 * Murmur site behaviour.
 *
 * Three small things, no framework and no network access: restore the stored
 * appearance before first paint, switch the code tabs, and copy the install
 * command. The script is loaded from <head> without `defer` so the appearance
 * class is on <html> before the body is painted.
 */

(function () {
    "use strict";

    var STORAGE_KEY = "murmur-site-appearance";
    var LIGHT_CLASS = "happy-theme-light";
    var DARK_CLASS = "happy-theme-dark";

    /** Reads the persisted appearance, tolerating a blocked or absent storage. */
    function storedAppearance() {
        try {
            var value = window.localStorage.getItem(STORAGE_KEY);
            return value === "light" || value === "dark" ? value : null;
        } catch {
            return null;
        }
    }

    /** Persists the appearance, tolerating a blocked or absent storage. */
    function persistAppearance(appearance) {
        try {
            window.localStorage.setItem(STORAGE_KEY, appearance);
        } catch {
            /* A private-mode storage rejection only costs the preference. */
        }
    }

    /** Applies one appearance to the single application tree on <html>. */
    function applyAppearance(appearance) {
        var root = document.documentElement;
        root.classList.remove(LIGHT_CLASS, DARK_CLASS);
        if (appearance === "light") root.classList.add(LIGHT_CLASS);
        if (appearance === "dark") root.classList.add(DARK_CLASS);
    }

    /** The appearance the page is currently painted in, explicit or ambient. */
    function currentAppearance() {
        var explicit = storedAppearance();
        if (explicit !== null) return explicit;
        return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    }

    // Before first paint.
    applyAppearance(storedAppearance());

    function setUpAppearanceToggle() {
        var toggle = document.getElementById("appearance-toggle");
        if (toggle === null) return;

        function render() {
            var dark = currentAppearance() === "dark";
            toggle.textContent = dark ? "Light" : "Dark";
            toggle.setAttribute("aria-pressed", dark ? "true" : "false");
            toggle.setAttribute(
                "aria-label",
                dark ? "Switch to light appearance" : "Switch to dark appearance",
            );
        }

        toggle.addEventListener("click", function () {
            var next = currentAppearance() === "dark" ? "light" : "dark";
            persistAppearance(next);
            applyAppearance(next);
            render();
        });

        render();
    }

    function setUpTabs() {
        var tablist = document.querySelector('[role="tablist"]');
        if (tablist === null) return;

        var tabs = Array.prototype.slice.call(tablist.querySelectorAll('[role="tab"]'));
        if (tabs.length === 0) return;

        function select(target, moveFocus) {
            tabs.forEach(function (tab) {
                var selected = tab === target;
                tab.setAttribute("aria-selected", selected ? "true" : "false");
                tab.tabIndex = selected ? 0 : -1;

                var panel = document.getElementById(tab.getAttribute("aria-controls"));
                if (panel !== null) panel.hidden = !selected;
            });
            if (moveFocus) target.focus();
        }

        tabs.forEach(function (tab, index) {
            tab.addEventListener("click", function () {
                select(tab, false);
            });

            tab.addEventListener("keydown", function (event) {
                var offset = 0;
                if (event.key === "ArrowRight") offset = 1;
                if (event.key === "ArrowLeft") offset = -1;
                if (offset === 0) return;
                event.preventDefault();
                select(tabs[(index + offset + tabs.length) % tabs.length], true);
            });
        });
    }

    function setUpCopyButton() {
        var button = document.getElementById("copy-install");
        var command = document.getElementById("install-command");
        var status = document.getElementById("copy-status");
        if (button === null || command === null) return;

        if (navigator.clipboard === undefined) {
            button.hidden = true;
            return;
        }

        button.addEventListener("click", function () {
            navigator.clipboard.writeText(command.textContent.trim()).then(
                function () {
                    button.textContent = "Copied";
                    if (status !== null) status.textContent = "Install command copied.";
                    window.setTimeout(function () {
                        button.textContent = "Copy";
                    }, 1500);
                },
                function () {
                    if (status !== null)
                        status.textContent = "Copying failed. Select the command instead.";
                },
            );
        });
    }

    document.addEventListener("DOMContentLoaded", function () {
        setUpAppearanceToggle();
        setUpTabs();
        setUpCopyButton();
    });
})();
