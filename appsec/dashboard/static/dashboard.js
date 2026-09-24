/* Progressive enhancement only; navigation, filters and downloads work without JS. */
document.querySelectorAll("[data-copy]").forEach((button) => {
  button.addEventListener("click", async () => {
    const target = document.getElementById(button.dataset.copy);
    const status = button.nextElementSibling;
    try {
      await navigator.clipboard.writeText(target.textContent);
      status.textContent = "Copied.";
    } catch {
      status.textContent = "Select the text above to copy it.";
    }
  });
});

/* Filters reload server-rendered results; say so while the request is in flight. */
const loading = document.getElementById("loading-status");
const filterButtons = () => document.querySelectorAll("form[method=get] button[type=submit]");
document.querySelectorAll("form[method=get]").forEach((form) => {
  form.addEventListener("submit", () => {
    loading.textContent = "Loading results…";
    loading.hidden = false;
    filterButtons().forEach((button) => { button.disabled = true; });
  });
});
/* Pages restored from the back/forward cache must not stay in the loading state. */
window.addEventListener("pageshow", () => {
  loading.hidden = true;
  filterButtons().forEach((button) => { button.disabled = false; });
});
