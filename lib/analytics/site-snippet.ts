// Build the JS snippet that the deployed site can `<script src=…>` from
// `/api/[owner]/[repo]/[branch]/analytics/snippet.js`.
//
// We don't want the deployed site to import the CMS at build time — that
// would couple their build to our schema. Instead, the site embeds a single
// script tag and we serve a small JS bundle that:
//
//   1. Honors DNT/Sec-GPC if `honorDnt` is on.
//   2. Shows a minimal consent banner if `requireConsent` is on, and only
//      injects provider tags after the user accepts (decision stored in
//      localStorage `pcms.consent`).
//   3. Injects GA4 / Plausible / Cloudflare Web Analytics tags as
//      configured.

export type SiteAnalyticsConfig = {
  ga4MeasurementId: string | null;
  plausibleDomain: string | null;
  plausibleApiHost: string | null;
  cfBeaconToken: string | null;
  requireConsent: boolean;
  honorDnt: boolean;
};

const escape = (value: string): string =>
  value.replace(/[\\"`<>]/g, (ch) => `\\u00${ch.charCodeAt(0).toString(16).padStart(2, "0")}`);

const json = (value: unknown): string => JSON.stringify(value);

export function generateSiteAnalyticsScript(config: SiteAnalyticsConfig): string {
  const ga4 = config.ga4MeasurementId ? escape(config.ga4MeasurementId) : null;
  const plausibleDomain = config.plausibleDomain ? escape(config.plausibleDomain) : null;
  const plausibleHost = config.plausibleApiHost ? escape(config.plausibleApiHost) : "https://plausible.io";
  const cfToken = config.cfBeaconToken ? escape(config.cfBeaconToken) : null;

  // The runtime is intentionally tiny: no framework, no bundler, no Promise
  // tricks. It must work in any deployed site without polyfills.
  return `(function(){
  var providers = {
    ga4: ${ga4 ? `"${ga4}"` : "null"},
    plausibleDomain: ${plausibleDomain ? `"${plausibleDomain}"` : "null"},
    plausibleHost: "${plausibleHost}",
    cfBeaconToken: ${cfToken ? `"${cfToken}"` : "null"}
  };
  var requireConsent = ${json(!!config.requireConsent)};
  var honorDnt = ${json(!!config.honorDnt)};

  function dnt(){ try { return navigator.doNotTrack === "1" || window.doNotTrack === "1" || navigator.globalPrivacyControl === true; } catch(e){ return false; } }
  if (honorDnt && dnt()) return;

  function inject(){
    if (providers.ga4){
      var s = document.createElement("script");
      s.async = true;
      s.src = "https://www.googletagmanager.com/gtag/js?id=" + encodeURIComponent(providers.ga4);
      document.head.appendChild(s);
      window.dataLayer = window.dataLayer || [];
      window.gtag = window.gtag || function(){ window.dataLayer.push(arguments); };
      window.gtag("js", new Date());
      window.gtag("config", providers.ga4, { anonymize_ip: true });
    }
    if (providers.plausibleDomain){
      var p = document.createElement("script");
      p.defer = true;
      p.setAttribute("data-domain", providers.plausibleDomain);
      p.src = providers.plausibleHost.replace(/\\/$/, "") + "/js/script.js";
      document.head.appendChild(p);
    }
    if (providers.cfBeaconToken){
      var c = document.createElement("script");
      c.defer = true;
      c.src = "https://static.cloudflareinsights.com/beacon.min.js";
      c.setAttribute("data-cf-beacon", '{"token":"' + providers.cfBeaconToken + '"}');
      document.head.appendChild(c);
    }
  }

  function showBanner(){
    if (document.getElementById("pcms-consent")) return;
    var b = document.createElement("div");
    b.id = "pcms-consent";
    b.style.cssText = "position:fixed;left:1rem;right:1rem;bottom:1rem;max-width:34rem;margin:0 auto;padding:0.875rem 1rem;background:#111;color:#fff;font:14px/1.4 system-ui,sans-serif;border-radius:0.5rem;display:flex;gap:0.75rem;align-items:center;z-index:2147483647;box-shadow:0 6px 24px rgba(0,0,0,0.25)";
    b.innerHTML = "<span style=\\"flex:1\\">We use minimal analytics to improve this site.</span><button type=\\"button\\" id=\\"pcms-consent-decline\\" style=\\"background:transparent;color:#fff;border:1px solid #555;padding:0.4rem 0.75rem;border-radius:0.375rem;cursor:pointer\\">Decline</button><button type=\\"button\\" id=\\"pcms-consent-accept\\" style=\\"background:#fff;color:#111;border:0;padding:0.4rem 0.75rem;border-radius:0.375rem;cursor:pointer\\">Accept</button>";
    document.body.appendChild(b);
    document.getElementById("pcms-consent-accept").addEventListener("click", function(){
      try { localStorage.setItem("pcms.consent", "granted"); } catch(e){}
      b.remove();
      inject();
    });
    document.getElementById("pcms-consent-decline").addEventListener("click", function(){
      try { localStorage.setItem("pcms.consent", "denied"); } catch(e){}
      b.remove();
    });
  }

  function ready(fn){
    if (document.readyState === "loading"){ document.addEventListener("DOMContentLoaded", fn); }
    else { fn(); }
  }

  ready(function(){
    if (!requireConsent){ inject(); return; }
    var prior = null;
    try { prior = localStorage.getItem("pcms.consent"); } catch(e){}
    if (prior === "granted"){ inject(); return; }
    if (prior === "denied"){ return; }
    showBanner();
  });
})();`;
}
