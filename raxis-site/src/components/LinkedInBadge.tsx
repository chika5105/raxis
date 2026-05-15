"use client";

import { useEffect } from "react";

export function LinkedInBadge() {
  useEffect(() => {
    // Avoid duplicate script injection
    const existing = document.querySelector(
      'script[src="https://platform.linkedin.com/badges/js/profile.js"]'
    );
    if (existing) {
      // Re-trigger badge rendering if script already loaded
      // @ts-expect-error linkedin global injected by their script
      if (typeof window.LIRenderAll === "function") window.LIRenderAll();
      return;
    }
    const script = document.createElement("script");
    script.src = "https://platform.linkedin.com/badges/js/profile.js";
    script.async = true;
    script.defer = true;
    document.body.appendChild(script);
  }, []);

  return (
    <div
      className="badge-base LI-profile-badge"
      data-locale="en_US"
      data-size="medium"
      data-theme="light"
      data-type="VERTICAL"
      data-vanity="chika-jinanwa"
      data-version="v1"
    >
      <a
        className="badge-base__link LI-simple-link"
        href="https://www.linkedin.com/in/chika-jinanwa?trk=profile-badge"
        target="_blank"
        rel="noopener noreferrer"
      >
        Chika Jinanwa
      </a>
    </div>
  );
}
