/**
 * Headless framer-motion verification for the AICore web app.
 *
 * Proves the motion runtime resolves and renders in this workspace without a
 * browser (Playwright's browser CDN is blocked in some environments — this
 * check always works). Plain Node + ESM, so it runs anywhere the app builds.
 *
 *   npm run verify:motion --workspace @aicore/web
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { createRequire } from "node:module";

import { createElement as h } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { AnimatePresence, motion, useMotionValue, useSpring, useTransform } from "framer-motion";

const require = createRequire(import.meta.url);

let failures = 0;
function check(label, ok, evidence = "") {
  console.log(`  ${ok ? "✓" : "✗"} ${label}${evidence ? ` — ${evidence}` : ""}`);
  if (!ok) failures++;
}

function resolveVersion() {
  try {
    const entry = require.resolve("framer-motion");
    let dir = dirname(entry);
    for (let depth = 0; depth < 5; depth += 1) {
      try {
        const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
        if (pkg.name === "framer-motion" && pkg.version) return pkg.version;
      } catch {
        /* keep walking up */
      }
      dir = dirname(dir);
    }
  } catch {
    /* fall through */
  }
  return "unknown";
}

const card = renderToStaticMarkup(
  h(
    motion.div,
    {
      initial: { opacity: 0, y: 12 },
      animate: { opacity: 1, y: 0 },
      transition: { type: "spring", stiffness: 220, damping: 28 },
    },
    "aicore",
  ),
);
check("motion.div renders", card.includes("aicore"), `${card.slice(0, 64)}…`);
check("inline animation style emitted", /opacity|transform/.test(card));

const list = renderToStaticMarkup(
  h(
    motion.ul,
    { variants: { show: { transition: { staggerChildren: 0.06 } } }, initial: "hidden", animate: "show" },
    h(motion.li, { variants: { hidden: { opacity: 0 }, show: { opacity: 1 } } }, "health"),
  ),
);
check("variants + staggerChildren render", list.includes("health"));

const presence = renderToStaticMarkup(
  h(
    AnimatePresence,
    null,
    h(motion.span, { key: "k", initial: { opacity: 0 }, animate: { opacity: 1 }, exit: { opacity: 0 } }, "proxied"),
  ),
);
check("AnimatePresence renders children", presence.includes("proxied"));

check("useSpring exported", typeof useSpring === "function");
check("useTransform exported", typeof useTransform === "function");
check("useMotionValue exported", typeof useMotionValue === "function");
check(
  "motion factory exported",
  (typeof motion === "function" || typeof motion === "object") &&
    (typeof motion.div === "object" || typeof motion.div === "function"),
  `motion=${typeof motion}, motion.div=${typeof motion.div}`,
);

const version = resolveVersion();
console.log(
  `\n  framer-motion@${version} — ${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`,
);
process.exit(failures === 0 ? 0 : 1);
