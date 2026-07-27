document.addEventListener("DOMContentLoaded", () => {
  const printButton = document.querySelector("[data-print-report]");
  if (printButton) {
    printButton.addEventListener("click", () => window.print());
  }

  const themeSelect = document.querySelector(".theme-form select");
  if (themeSelect) {
    themeSelect.addEventListener("change", () => themeSelect.form.submit());
  }

  const reportForm = document.querySelector("[data-report-form]");
  if (!reportForm) {
    return;
  }

  const fileInput = reportForm.querySelector("[data-report-file]");
  const fileName = reportForm.querySelector("[data-file-name]");
  const uploadZone = reportForm.querySelector("[data-upload-zone]");
  const submitButton = reportForm.querySelector("[data-submit-report]");
  const submitLabel = reportForm.querySelector("[data-submit-label]");
  const formatLabels = {
    preview: "Build preview",
    xlsx: "Download Excel",
    csv: "Download CSV",
    html: "Download HTML",
  };

  const showSelectedFile = () => {
    const selected = fileInput.files && fileInput.files[0];
    fileName.textContent = selected ? selected.name : "or drag and drop it here";
  };

  fileInput.addEventListener("change", showSelectedFile);
  uploadZone.addEventListener("dragover", () => uploadZone.classList.add("is-dragging"));
  uploadZone.addEventListener("dragleave", () => uploadZone.classList.remove("is-dragging"));
  uploadZone.addEventListener("drop", () => {
    uploadZone.classList.remove("is-dragging");
    window.setTimeout(showSelectedFile, 0);
  });

  reportForm.querySelectorAll('input[name="format"]').forEach((option) => {
    option.addEventListener("change", () => {
      submitLabel.textContent = formatLabels[option.value] || "Process report";
    });
  });

  reportForm.addEventListener("submit", () => {
    submitButton.disabled = true;
    submitLabel.textContent = "Processing report...";
  });
});
