export type Tool = {
  name: string;
  role: string;
  detail: string;
  status: 'installed' | 'installed-partial';
  accent: string;
  installPath: string;
  trigger: string;
};

export const tools: Tool[] = [
  {
    name: 'gstack',
    role: 'Virtual engineering team',
    detail:
      '55 skills from Garry Tan: /office-hours, /autoplan, /plan-ceo-review, /plan-eng-review, /review, /qa, /ship, /cso, /browse, /retro.',
    status: 'installed',
    accent: '#6d5efc',
    installPath: '~/.claude/skills/gstack-*',
    trigger: 'Load gstack. Run /office-hours',
  },
  {
    name: 'superpowers',
    role: 'Development methodology',
    detail:
      'obra’s 14 composable skills: brainstorming, writing-plans, TDD, subagent-driven-development, systematic-debugging, verification-before-completion.',
    status: 'installed',
    accent: '#e5484d',
    installPath: '.agents/skills/* (vendored) + ~/.claude/skills/*',
    trigger: 'Brainstorm → plan → TDD → verify',
  },
  {
    name: 'ruflo',
    role: 'Agent meta-harness',
    detail:
      'claude-flow v3 scaffolding: agents, commands, skills, hooks, MCP server (353 tools), swarm + self-learning memory.',
    status: 'installed-partial',
    accent: '#0ea5a5',
    installPath: '.claude/, .claude-flow/, .mcp.json',
    trigger: 'npx ruflo@latest doctor',
  },
  {
    name: '21st.dev',
    role: 'React component registry + MCP',
    detail:
      'Component/template search, AI UI generation, MCP server (https://21st.dev/api/mcp), design context in .21st/DESIGN.md.',
    status: 'installed',
    accent: '#f5a524',
    installPath: '.mcp.json (21st) + .21st/',
    trigger: 'npx @21st-dev/cli@latest search "pricing card"',
  },
  {
    name: 'framer-motion',
    role: 'Animation runtime',
    detail:
      'Motion for React: springs, gestures, layout animations, AnimatePresence. Wired into this Vite + React + Tailwind app.',
    status: 'installed',
    accent: '#3b82f6',
    installPath: 'node_modules/framer-motion',
    trigger: 'import { motion } from "framer-motion"',
  },
];
