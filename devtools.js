// Creates the DevTools panel. Runs once per DevTools window.
chrome.devtools.panels.create(
  "API Sniffer",
  "",
  "panel.html",
  (panel) => {
    console.log("[API Sniffer Pro] panel created");
    // Keep the panel alive indicator
    panel.onShown.addListener(() => console.log("[API Sniffer Pro] panel shown"));
  }
);