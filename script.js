async function handleWorkinkClick() {
  if (!isAuthenticated) {
    openAuthModal(); // Minta login dulu
    return;
  }

  try {
    showLoading("Mengarahkan ke Work.ink...");
    const res = await fetch("/api?action=workink", { credentials: "include" });
    const data = await res.json();
    hideLoading();
    
    if (res.ok) {
      window.location.href = data.workink_url;
    } else {
      alert("Gagal generate link");
    }
  } catch (error) {
    hideLoading();
    alert("Terjadi error");
  }
}
