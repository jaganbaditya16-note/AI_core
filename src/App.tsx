import { useState } from 'react';
import {
  AnimatePresence,
  motion,
  useMotionValue,
  useSpring,
  useTransform,
  type Variants,
} from 'framer-motion';
import { tools, type Tool } from './data/toolkit';

const container: Variants = {
  hidden: {},
  show: { transition: { staggerChildren: 0.07, delayChildren: 0.1 } },
};

const item: Variants = {
  hidden: { opacity: 0, y: 18, filter: 'blur(6px)' },
  show: {
    opacity: 1,
    y: 0,
    filter: 'blur(0px)',
    transition: { type: 'spring', stiffness: 220, damping: 26 },
  },
};

function StatusPill({ status }: { status: Tool['status'] }) {
  const partial = status === 'installed-partial';
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-medium ring-1 ${
        partial
          ? 'bg-amber-400/10 text-amber-300 ring-amber-400/30'
          : 'bg-emerald-400/10 text-emerald-300 ring-emerald-400/30'
      }`}
    >
      <motion.span
        className={`size-1.5 rounded-full ${partial ? 'bg-amber-300' : 'bg-emerald-300'}`}
        animate={{ opacity: [1, 0.35, 1], scale: [1, 0.85, 1] }}
        transition={{ duration: 2.2, repeat: Infinity, ease: 'easeInOut' }}
      />
      {partial ? 'installed (1 module limited)' : 'installed'}
    </span>
  );
}

function ToolCard({ tool }: { tool: Tool }) {
  return (
    <motion.article
      variants={item}
      whileHover={{ y: -6, rotateX: 3, rotateY: -3 }}
      transition={{ type: 'spring', stiffness: 300, damping: 22 }}
      style={{ transformPerspective: 900 }}
      className="group relative flex flex-col gap-3 overflow-hidden rounded-2xl bg-white/[0.04] p-5 ring-1 ring-white/10 backdrop-blur-xl"
    >
      <div
        className="pointer-events-none absolute -top-24 -right-16 size-48 rounded-full opacity-25 blur-3xl transition-opacity duration-500 group-hover:opacity-45"
        style={{ background: tool.accent }}
      />
      <header className="flex items-start justify-between gap-3">
        <div>
          <h3 className="font-mono text-base font-semibold tracking-tight text-white">
            {tool.name}
          </h3>
          <p className="text-xs text-white/55">{tool.role}</p>
        </div>
        <StatusPill status={tool.status} />
      </header>

      <p className="text-sm leading-relaxed text-white/75">{tool.detail}</p>

      <dl className="mt-auto grid gap-1 font-mono text-[11px] text-white/45">
        <div className="flex gap-2">
          <dt className="shrink-0 text-white/35">path</dt>
          <dd className="truncate">{tool.installPath}</dd>
        </div>
        <div className="flex gap-2">
          <dt className="shrink-0 text-white/35">use</dt>
          <dd className="truncate text-white/60">{tool.trigger}</dd>
        </div>
      </dl>
    </motion.article>
  );
}

function SpringPlayground() {
  const [on, setOn] = useState(false);
  const x = useMotionValue(0);
  const spring = useSpring(x, { stiffness: 260, damping: 18, mass: 0.6 });
  const width = useTransform(spring, (v) => `${34 + v}%`);

  return (
    <section className="rounded-2xl bg-white/[0.03] p-5 ring-1 ring-white/10">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-white/90">Motion runtime check</h2>
        <button
          type="button"
          onClick={() => {
            const next = !on;
            setOn(next);
            x.set(next ? 66 : 0);
          }}
          className="rounded-full bg-white/10 px-3 py-1.5 text-xs font-medium text-white/85 ring-1 ring-white/15 transition hover:bg-white/15"
        >
          {on ? 'reset spring' : 'release spring'}
        </button>
      </div>

      <div className="h-3 w-full overflow-hidden rounded-full bg-white/10">
        <motion.div
          className="h-full rounded-full bg-gradient-to-r from-indigo-400 via-fuchsia-400 to-amber-300"
          style={{ width }}
        />
      </div>

      <div className="mt-5 flex flex-wrap gap-2">
        {tools.map((tool, index) => (
          <motion.span
            key={tool.name}
            layout
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ type: 'spring', stiffness: 320, damping: 24, delay: index * 0.04 }}
            className="rounded-lg bg-white/[0.06] px-2.5 py-1 font-mono text-[11px] text-white/70 ring-1 ring-white/10"
          >
            {tool.name}
          </motion.span>
        ))}
      </div>
    </section>
  );
}

function Drawer() {
  const [open, setOpen] = useState(true);
  return (
    <section className="rounded-2xl bg-white/[0.03] p-5 ring-1 ring-white/10">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-white/90">Session protocol</h2>
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          className="rounded-full bg-white/10 px-3 py-1.5 text-xs font-medium text-white/85 ring-1 ring-white/15 transition hover:bg-white/15"
        >
          {open ? 'hide' : 'show'}
        </button>
      </div>

      <AnimatePresence initial={false} mode="wait">
        {open && (
          <motion.ol
            key="protocol"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
            className="space-y-2 overflow-hidden text-sm text-white/70"
          >
            {[
              'superpowers: brainstorm the spec before code',
              'gstack: /office-hours → /autoplan → implement',
              'ruflo: swarm + agents for parallel workstreams',
              '21st.dev: pull real components, no invented UI',
              'framer-motion: animate it, then /review + /qa',
            ].map((line, i) => (
              <motion.li
                key={line}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.06 * i + 0.1 }}
                className="flex gap-2"
              >
                <span className="font-mono text-white/30">{i + 1}.</span>
                <span>{line}</span>
              </motion.li>
            ))}
          </motion.ol>
        )}
      </AnimatePresence>
    </section>
  );
}

export default function App() {
  return (
    <main className="mx-auto max-w-6xl px-5 py-14 sm:px-8">
      <motion.header
        initial={{ opacity: 0, y: -14 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ type: 'spring', stiffness: 180, damping: 24 }}
        className="mb-10"
      >
        <p className="mb-2 font-mono text-xs tracking-[0.3em] text-white/40 uppercase">
          control room
        </p>
        <h1 className="bg-gradient-to-br from-white via-white to-indigo-300 bg-clip-text text-4xl font-semibold tracking-tight text-transparent sm:text-5xl">
          AI Core
        </h1>
        <p className="mt-3 max-w-2xl text-sm leading-relaxed text-white/60">
          Every tool below is wired into this workspace and is expected to be used on{' '}
          <span className="text-white/85">every</span> build request: gstack for the engineering
          roles, superpowers for the methodology, ruflo for agents and memory, 21st.dev for real UI
          components, framer-motion for motion.
        </p>
      </motion.header>

      <motion.div
        variants={container}
        initial="hidden"
        animate="show"
        className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3"
      >
        {tools.map((tool) => (
          <ToolCard key={tool.name} tool={tool} />
        ))}
      </motion.div>

      <div className="mt-6 grid gap-4 lg:grid-cols-2">
        <SpringPlayground />
        <Drawer />
      </div>

      <motion.footer
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.5 }}
        className="mt-10 space-y-1 font-mono text-[11px] text-white/35"
      >
        <p>npm install framer-motion · yarn add framer-motion</p>
        <p>bash scripts/toolkit-status.sh — verify every integration</p>
        <p>bash scripts/bootstrap.sh — restore node_modules + tools after a fresh clone</p>
      </motion.footer>
    </main>
  );
}
