"use client";

import { motion, useReducedMotion } from "framer-motion";
import type { ReactNode } from "react";

/**
 * Minimal motion wrapper.
 *
 * framer-motion is used sparingly in Phase 0 — a single entrance transition for
 * page-level content. Reduced-motion users get the static layout.
 */
export function FadeIn({ children, delay = 0 }: { children: ReactNode; delay?: number }) {
  const reduceMotion = useReducedMotion();

  if (reduceMotion) {
    return <>{children}</>;
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ type: "spring", stiffness: 220, damping: 28, delay }}
    >
      {children}
    </motion.div>
  );
}
