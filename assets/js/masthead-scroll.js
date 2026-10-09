(() => {
  const init = () => {
    const masthead = document.querySelector(".masthead");
    if (!masthead) return;

    let lastY = Math.max(window.scrollY, 0);
    let ticking = false;

    const update = () => {
      const currentY = Math.max(window.scrollY, 0);
      const delta = currentY - lastY;

      if (currentY <= masthead.offsetHeight) {
        masthead.classList.remove("masthead--hidden");
      } else if (delta > 4) {
        masthead.classList.add("masthead--hidden");
      } else if (delta < -4) {
        masthead.classList.remove("masthead--hidden");
      }

      lastY = currentY;
      ticking = false;
    };

    window.addEventListener("scroll", () => {
      if (!ticking) {
        window.requestAnimationFrame(update);
        ticking = true;
      }
    }, { passive: true });

    masthead.addEventListener("focusin", () => {
      masthead.classList.remove("masthead--hidden");
    });
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})();
