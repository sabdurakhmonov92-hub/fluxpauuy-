// FluxPay Dashboard Client Enhancements (Task 62)
// ZERO inline JS, progressive enhancement, native htmx event hooks.

document.addEventListener("DOMContentLoaded", function () {
  // 1. One-time Secret Copy-to-Clipboard Action
  document.addEventListener("click", function (event) {
    var button = event.target.closest("[data-copy-target]");
    if (!button) return;

    var targetId = button.getAttribute("data-copy-target");
    var targetEl = document.getElementById(targetId);
    if (!targetEl) return;

    var text = targetEl.textContent || targetEl.innerText || "";
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text.trim()).then(function () {
        var originalText = button.textContent;
        button.textContent = "Copied!";
        button.disabled = true;
        setTimeout(function () {
          button.textContent = originalText;
          button.disabled = false;
        }, 2000);
      });
    }
  });

  // 2. HTMX Response Error Toast Notification
  document.body.addEventListener("htmx:responseError", function (event) {
    var detail = event.detail;
    var status = detail.xhr ? detail.xhr.status : "Error";
    var toast = document.createElement("div");
    toast.className = "toast toast-danger";
    toast.textContent = "Action failed: Server returned HTTP " + status;
    document.body.appendChild(toast);
    setTimeout(function () {
      toast.remove();
    }, 4000);
  });
});
