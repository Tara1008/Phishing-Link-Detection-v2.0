import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import {
  Shield, Zap, Lock, BarChart3, Globe, ArrowRight,
  ChevronDown, ChevronUp, Brain, Database
} from 'lucide-react';
import { useState } from 'react';

const FEATURES = [
  { icon: Zap,       title: 'URL-only Analysis',       desc: 'The scanner parses the submitted URL and does not visit or fetch the destination website.' },
  { icon: Brain,     title: 'Hybrid Risk Assessment',  desc: 'A Random Forest and XGBoost ensemble is combined with URL-based security heuristics.' },
  { icon: BarChart3, title: 'Explainable Signals',     desc: 'Review the URL features, risk indicators, and relative model signal weights behind each result.' },
  { icon: Database,  title: 'Scan History',            desc: 'History uses MySQL when configured and available; otherwise the backend falls back to local JSON storage.' },
  { icon: Lock,      title: 'Score and Grade',         desc: 'Each scan returns a 0–100 risk score, a Safe/Suspicious/Phishing classification, and an A–F grade.' },
  { icon: Globe,     title: 'URL Breakdown',            desc: 'Inspect the parsed protocol, domain, subdomains, path, TLD, and extracted URL features.' },
];

const STATS = [
  { value: '26',      label: 'Model Input Features' },
  { value: '3',       label: 'Risk Classifications' },
  { value: 'A–F',     label: 'Security Grades' },
  { value: 'URL-only',label: 'No Target Visits' },
];

const HOW_IT_WORKS = [
  { step: '01', title: 'Submit a URL',        desc: 'Paste a URL (up to 2,048 characters). If no scheme is supplied, it is parsed as HTTP.' },
  { step: '02', title: 'Extract features',    desc: 'The backend parses URL structure and builds a 26-value feature vector.' },
  { step: '03', title: 'Assess risk',          desc: 'An ensemble prediction is blended with security heuristics and threat safeguards.' },
  { step: '04', title: 'Review the result',    desc: 'See the score, classification, grade, explanations, URL breakdown, and recommendation.' },
];

const RESULT_GUIDE = [
  { score: '0–30', classification: 'Safe', description: 'No strong phishing indicators were found by this URL-based assessment.' },
  { score: '31–60', classification: 'Suspicious', description: 'Some risk indicators were found. Verify the domain before interacting with the site.' },
  { score: '61–100', classification: 'Phishing', description: 'The URL has strong risk indicators. Do not enter sensitive information.' },
];

const FAQS = [
  { q: 'How should I interpret the risk score?', a: 'The score ranges from 0 to 100. Scores 0–30 are classified Safe, 31–60 Suspicious, and 61–100 Phishing. The A–F grade uses separate score bands. These are automated URL assessments, not guarantees about the live site.' },
  { q: 'Does the scanner open or check the website?', a: 'No. It analyzes the submitted URL text and its parsed features; it does not send a request to the destination, follow redirects, or inspect page content.' },
  { q: 'How does the risk assessment work?', a: 'The backend extracts URL features, evaluates them with a Random Forest and XGBoost ensemble, then blends that model score with security heuristics and safeguards.' },
  { q: 'What does confidence mean?', a: 'Confidence reflects model consensus, agreement, and how decisive its prediction is. It is not a measured accuracy rate or a guarantee that the classification is correct.' },
  { q: 'Where is scan history stored?', a: 'The backend uses MySQL when valid MySQL settings are configured and the database is reachable. Otherwise it falls back to a local JSON file. On serverless hosts such as Vercel, local files may not persist across instances or deployments.' },
  { q: 'Can I call the API directly?', a: 'Yes. The backend provides POST /api/analyze and GET /api/history, among other endpoints. Analysis requests accept a URL string up to 2,048 characters.' },
];

function FAQItem({ q, a }: { q: string; a: string }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="border border-slate-200 dark:border-slate-700 rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-5 py-4 text-left hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors"
      >
        <span className="font-medium text-slate-800 dark:text-slate-200 text-sm">{q}</span>
        {open ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
      </button>
      {open && (
        <motion.div
          initial={{ height: 0 }}
          animate={{ height: 'auto' }}
          className="px-5 pb-4"
        >
          <p className="text-sm text-slate-500 dark:text-slate-400 leading-relaxed">{a}</p>
        </motion.div>
      )}
    </div>
  );
}

const stagger = {
  container: { hidden: {}, show: { transition: { staggerChildren: 0.1 } } },
  item:      { hidden: { opacity: 0, y: 24 }, show: { opacity: 1, y: 0, transition: { duration: 0.5 } } },
};

export default function LandingPage() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen overflow-hidden">
      {/* ── Hero ─────────────────────────────────────────────────── */}
      <section className="relative min-h-screen flex items-center justify-center px-4 pb-16 overflow-hidden">
        {/* Animated gradient blobs */}
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          <div className="absolute top-1/4 -left-32 w-96 h-96 bg-indigo-200/40 dark:bg-indigo-900/20 rounded-full blob blur-3xl" />
          <div className="absolute top-1/3 -right-32 w-96 h-96 bg-purple-200/40 dark:bg-purple-900/20 rounded-full blob blob-delay-2 blur-3xl" />
          <div className="absolute bottom-1/4 left-1/2 w-80 h-80 bg-teal-200/30 dark:bg-teal-900/15 rounded-full blob blob-delay-4 blur-3xl" />
        </div>

        {/* Grid overlay */}
        <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PGRlZnM+PHBhdHRlcm4gaWQ9ImdyaWQiIHdpZHRoPSI2MCIgaGVpZ2h0PSI2MCIgcGF0dGVyblVuaXRzPSJ1c2VyU3BhY2VPblVzZSI+PHBhdGggZD0iTSAxMCAwIEwgMCAwIDAgMTAiIGZpbGw9Im5vbmUiIHN0cm9rZT0iIzYzNjZmMSIgc3Ryb2tlLXdpZHRoPSIwLjMiIG9wYWNpdHk9IjAuMyIvPjwvcGF0dGVybj48L2RlZnM+PHJlY3Qgd2lkdGg9IjEwMCUiIGhlaWdodD0iMTAwJSIgZmlsbD0idXJsKCNncmlkKSIvPjwvc3ZnPg==')] opacity-40 dark:opacity-20 pointer-events-none" />

        <div className="relative z-10 w-full max-w-5xl mx-auto text-center">
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-indigo-50 dark:bg-indigo-950/50 border border-indigo-200 dark:border-indigo-800 text-indigo-600 dark:text-indigo-400 text-sm font-semibold mb-6"
          >
            <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
            URL-only · Hybrid scoring · Explainable
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.1 }}
            className="text-4xl sm:text-6xl lg:text-7xl font-black text-slate-900 dark:text-white leading-tight tracking-tight mb-6"
          >
            Detect Phishing
            <br />
            <span className="gradient-text">Before It's Too Late</span>
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.2 }}
            className="text-lg sm:text-xl text-slate-500 dark:text-slate-400 max-w-2xl mx-auto mb-10 leading-relaxed"
          >
            PhishGuard AI evaluates URL structure with a hybrid model and security heuristics, then returns a risk score, classification, grade, and feature breakdown. It does not visit the destination website.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.3 }}
            className="flex flex-col sm:flex-row items-center justify-center gap-4"
          >
            <motion.button
              onClick={() => navigate('/scan')}
              whileHover={{ scale: 1.04 }}
              whileTap={{ scale: 0.97 }}
              className="flex items-center gap-2.5 px-8 py-4 bg-gradient-to-r from-indigo-500 via-purple-600 to-indigo-500
                         bg-size-200 text-white font-bold text-base rounded-2xl shadow-glow
                         hover:shadow-lg transition-all duration-300 animate-gradient"
            >
              <Shield className="w-5 h-5" />
              Start Scanning Free
              <ArrowRight className="w-4 h-4" />
            </motion.button>
            <button
              onClick={() => navigate('/tips')}
              className="flex items-center gap-2 px-6 py-4 text-slate-600 dark:text-slate-400 font-semibold text-base
                         border border-slate-200 dark:border-slate-700 rounded-2xl hover:border-indigo-300 dark:hover:border-indigo-700
                         hover:text-indigo-600 dark:hover:text-indigo-400 transition-all duration-200"
            >
              Learn about phishing
            </button>
          </motion.div>

          {/* Floating URL example card */}
          <motion.div
            initial={{ opacity: 0, y: 40 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.9, delay: 0.6 }}
            className="mt-16 w-full"
          >
            <div className="glass w-full max-w-lg rounded-2xl px-6 py-4 shadow-glass mx-auto text-left">
              <div className="flex items-center gap-2 mb-3">
                <div className="w-3 h-3 rounded-full bg-red-400" />
                <div className="w-3 h-3 rounded-full bg-amber-400" />
                <div className="w-3 h-3 rounded-full bg-green-400" />
                <span className="ml-2 text-xs text-slate-400 font-mono">Example scan result</span>
              </div>
              <div className="flex items-center gap-3 bg-slate-50 dark:bg-slate-800 rounded-xl px-4 py-2.5 font-mono text-sm text-slate-600 dark:text-slate-300">
                <span className="text-slate-400">🔗</span>
                <span className="flex-1 truncate">http://paypa1-secure-verify.tk/login</span>
                <span className="px-2 py-0.5 bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-400 text-xs font-bold rounded-full">PHISHING</span>
              </div>
              <div className="mt-3 grid grid-cols-3 gap-2 text-center">
                {[['Risk Score', '0–100', '#ef4444'], ['Grade', 'A–F', '#ef4444'], ['Confidence', 'Model estimate', '#6366f1']].map(([l, v, c]) => (
                  <div key={l} className="bg-white dark:bg-slate-900 rounded-lg p-2 border border-slate-100 dark:border-slate-700">
                    <div className="font-bold text-sm" style={{ color: c }}>{v}</div>
                    <div className="text-xs text-slate-400">{l}</div>
                  </div>
                ))}
              </div>
              <p className="mt-2 text-center text-xs text-slate-400">Illustrative labels only; actual results depend on the URL.</p>
            </div>
          </motion.div>
        </div>
      </section>

      {/* ── Stats ────────────────────────────────────────────────── */}
      <section className="py-16 bg-gradient-to-r from-indigo-500 via-purple-600 to-indigo-500 bg-size-200 animate-gradient">
        <div className="max-w-5xl mx-auto px-4 grid grid-cols-2 md:grid-cols-4 gap-8 text-center text-white">
          {STATS.map(({ value, label }, i) => (
            <motion.div
              key={label}
              initial={{ opacity: 0, y: 16 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.1 }}
            >
              <div className="text-4xl font-black mb-1">{value}</div>
              <div className="text-sm text-white/75 font-medium">{label}</div>
            </motion.div>
          ))}
        </div>
      </section>

      {/* ── Features ─────────────────────────────────────────────── */}
      <section className="py-24 px-4 bg-slate-50 dark:bg-slate-950/50">
        <div className="max-w-6xl mx-auto">
          <SectionHeader
            badge="Features"
            title="Tools to help assess URL risk"
            desc="Review URL-derived signals, model and heuristic assessments, and the reasoning behind each result."
          />
          <motion.div
            variants={stagger.container}
            initial="hidden"
            whileInView="show"
            viewport={{ once: true }}
            className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 mt-12"
          >
            {FEATURES.map(({ icon: Icon, title, desc }) => (
              <motion.div
                key={title}
                variants={stagger.item}
                whileHover={{ y: -4 }}
                className="bg-white dark:bg-slate-900 rounded-2xl p-6 border border-slate-200 dark:border-slate-700 shadow-card hover:shadow-lg transition-all duration-300"
              >
                <div className="w-10 h-10 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl flex items-center justify-center mb-4">
                  <Icon className="w-5 h-5 text-white" />
                </div>
                <h3 className="font-bold text-slate-900 dark:text-white mb-2">{title}</h3>
                <p className="text-sm text-slate-500 dark:text-slate-400 leading-relaxed">{desc}</p>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* ── How it works ─────────────────────────────────────────── */}
      <section className="py-24 px-4">
        <div className="max-w-4xl mx-auto">
          <SectionHeader badge="How it works" title="Four steps to assess a URL" desc="" />
          <div className="mt-12 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
            {HOW_IT_WORKS.map(({ step, title, desc }, i) => (
              <motion.div
                key={step}
                initial={{ opacity: 0, x: -16 }}
                whileInView={{ opacity: 1, x: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.12 }}
                className="relative text-center"
              >
                <div className="w-14 h-14 mx-auto bg-gradient-to-br from-indigo-500 to-purple-600 rounded-2xl flex items-center justify-center text-white font-black text-lg shadow-glow mb-4">
                  {step}
                </div>
                {i < 3 && <div className="hidden lg:block absolute top-7 left-[calc(50%+28px)] right-0 h-px border-t-2 border-dashed border-indigo-200 dark:border-indigo-900" />}
                <h3 className="font-bold text-slate-900 dark:text-white mb-1">{title}</h3>
                <p className="text-sm text-slate-500 dark:text-slate-400">{desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Result guide ─────────────────────────────────────────── */}
      <section className="py-24 px-4 bg-slate-50 dark:bg-slate-950/50">
        <div className="max-w-5xl mx-auto">
          <SectionHeader badge="Understanding results" title="What the score means" desc="Classification thresholds reflect the backend's current scoring logic. A score is an automated signal, not proof that a site is safe or malicious." />
          <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-6">
            {RESULT_GUIDE.map(({ score, classification, description }, i) => (
              <motion.div
                key={classification}
                initial={{ opacity: 0, y: 16 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.12 }}
                className="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-700 shadow-card"
              >
                <div className="text-sm font-semibold text-indigo-500 mb-2">{score} / 100</div>
                <h3 className="font-bold text-slate-900 dark:text-white mb-2">{classification}</h3>
                <p className="text-sm text-slate-500 dark:text-slate-400 leading-relaxed">{description}</p>
              </motion.div>
            ))}
          </div>
          <p className="text-xs text-center text-slate-400 dark:text-slate-500 mt-5">
            Grades use separate thresholds: A (0–20), B (21–40), C (41–60), D (61–80), and F (81–100).
          </p>
        </div>
      </section>

      {/* ── FAQ ──────────────────────────────────────────────────── */}
      <section className="py-24 px-4">
        <div className="max-w-3xl mx-auto">
          <SectionHeader badge="FAQ" title="Frequently Asked Questions" desc="" />
          <div className="mt-10 space-y-3">
            {FAQS.map(({ q, a }) => <FAQItem key={q} q={q} a={a} />)}
          </div>
        </div>
      </section>

      {/* ── CTA ──────────────────────────────────────────────────── */}
      <section className="py-20 px-4">
        <div className="max-w-3xl mx-auto text-center">
          <div className="relative rounded-3xl overflow-hidden p-12 bg-gradient-to-br from-indigo-500 via-purple-600 to-indigo-700 shadow-glow">
            <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PGRlZnM+PHBhdHRlcm4gaWQ9ImdyaWQiIHdpZHRoPSI2MCIgaGVpZ2h0PSI2MCIgcGF0dGVyblVuaXRzPSJ1c2VyU3BhY2VPblVzZSI+PHBhdGggZD0iTSAxMCAwIEwgMCAwIDAgMTAiIGZpbGw9Im5vbmUiIHN0cm9rZT0id2hpdGUiIHN0cm9rZS13aWR0aD0iMC4zIiBvcGFjaXR5PSIwLjIiLz48L3BhdHRlcm4+PC9kZWZzPjxyZWN0IHdpZHRoPSIxMDAlIiBoZWlnaHQ9IjEwMCUiIGZpbGw9InVybCgjZ3JpZCkiLz48L3N2Zz4=')] opacity-30" />
            <div className="relative z-10">
              <h2 className="text-3xl sm:text-4xl font-black text-white mb-4">Ready to scan your first URL?</h2>
              <p className="text-white/75 mb-8 text-lg">Free, instant, no signup required.</p>
              <motion.button
                onClick={() => navigate('/scan')}
                whileHover={{ scale: 1.04 }}
                whileTap={{ scale: 0.97 }}
                className="inline-flex items-center gap-2.5 px-8 py-4 bg-white text-indigo-600 font-bold text-base rounded-2xl shadow-lg hover:shadow-xl transition-all"
              >
                <Shield className="w-5 h-5" />
                Scan a URL Now
                <ArrowRight className="w-4 h-4" />
              </motion.button>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}

function SectionHeader({ badge, title, desc }: { badge: string; title: string; desc: string }) {
  return (
    <div className="text-center">
      <span className="inline-block px-3 py-1 text-xs font-bold uppercase tracking-widest text-indigo-600 dark:text-indigo-400 bg-indigo-50 dark:bg-indigo-950/50 border border-indigo-200 dark:border-indigo-800 rounded-full mb-4">
        {badge}
      </span>
      <h2 className="text-3xl sm:text-4xl font-black text-slate-900 dark:text-white mb-3">{title}</h2>
      {desc && <p className="text-slate-500 dark:text-slate-400 max-w-xl mx-auto">{desc}</p>}
    </div>
  );
}
