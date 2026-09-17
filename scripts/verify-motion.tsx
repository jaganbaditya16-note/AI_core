/**
 * Headless verification that framer-motion actually runs in this workspace.
 *
 * Renders real motion components through react-dom/server (no browser needed)
 * and asserts the library emitted its animation state. Run with:
 *
 *   npm run verify:motion          (bun scripts/verify-motion.tsx)
 */
import { renderToStaticMarkup } from 'react-dom/server';
import { AnimatePresence, motion, useSpring, useTransform } from 'framer-motion';
import { useMotionValue } from 'framer-motion';

let failures = 0;
function check(label: string, ok: boolean, evidence: string) {
  console.log(`  ${ok ? '✓' : '✗'} ${label}${evidence ? ` — ${evidence}` : ''}`);
  if (!ok) failures++;
}

// 1. motion elements render and emit inline animation styles
const card = renderToStaticMarkup(
  <motion.div
    initial={{ opacity: 0, y: 18 }}
    animate={{ opacity: 1, y: 0 }}
    transition={{ type: 'spring', stiffness: 220, damping: 26 }}
    data-testid="card"
  >
    hello
  </motion.div>,
);
check('motion.div renders', card.includes('hello'), card.slice(0, 72) + '…');
check('inline transform emitted', /transform|translate|opacity/.test(card), 'style attribute present');

// 2. variants + stagger configuration is accepted
const list = renderToStaticMarkup(
  <motion.ul variants={{ show: { transition: { staggerChildren: 0.07 } } }} initial="hidden" animate="show">
    <motion.li variants={{ hidden: { opacity: 0 }, show: { opacity: 1 } }}>one</motion.li>
    <motion.li variants={{ hidden: { opacity: 0 }, show: { opacity: 1 } }}>two</motion.li>
  </motion.ul>,
);
check('variants + staggerChildren render', list.includes('one') && list.includes('two'));

// 3. AnimatePresence passes mounted children through
const presence = renderToStaticMarkup(
  <AnimatePresence>
    <motion.span key="k" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
      present
    </motion.span>
  </AnimatePresence>,
);
check('AnimatePresence renders children', presence.includes('present'));

// 4. the hooks used by src/App.tsx exist and are callable
check('useSpring exported', typeof useSpring === 'function');
check('useTransform exported', typeof useTransform === 'function');
check('useMotionValue exported', typeof useMotionValue === 'function');
check(
  'motion factory exported',
  (typeof motion === 'function' || typeof motion === 'object') &&
    (typeof motion.div === 'object' || typeof motion.div === 'function'),
  `motion=${typeof motion}, motion.div=${typeof motion.div}`,
);

const version = (await import('framer-motion/package.json', { with: { type: 'json' } })).default.version;
console.log(`\n  framer-motion@${version} — ${failures === 0 ? 'ALL CHECKS PASSED' : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
