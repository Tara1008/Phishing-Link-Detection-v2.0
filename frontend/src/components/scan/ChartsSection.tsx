import {
  Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid
} from 'recharts';
import { motion } from 'framer-motion';
import type { ScanResult } from '../../types';
import { getRiskColor } from '../../types';

interface Props { result: ScanResult; }

export default function ChartsSection({ result }: Props) {
  const { reasons, risk_score } = result;

  // The score is a combined output, not a sum of individual risk buckets.
  const featureData = reasons
    .filter(reason => !reason.positive && reason.model_importance !== undefined)
    .map(reason => ({
      name: reason.label,
      value: Math.round((reason.model_importance ?? 0) * 100),
    }))
   .sort((a, b) => b.value - a.value)
   .slice(0, 6);

  const color = getRiskColor(risk_score);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <ChartCard title="Classification thresholds" subtitle={`Score ${risk_score}/100 · ${result.classification}`}>
        <div className="px-1 pt-8 pb-3">
          <div
            className="relative flex h-3 overflow-visible rounded-full"
            role="img"
            aria-label={`Risk score ${risk_score} out of 100. Safe is 0 to 30, suspicious is 31 to 60, and phishing is 61 to 100.`}
          >
            <div className="w-[30%] rounded-l-full bg-green-500" />
            <div className="w-[30%] bg-amber-400" />
            <div className="w-[40%] rounded-r-full bg-red-500" />
            <div
              className="absolute -top-7 -translate-x-1/2 whitespace-nowrap rounded-md bg-slate-900 px-2 py-1 text-xs font-bold text-white dark:bg-white dark:text-slate-900"
              style={{ left: `${risk_score}%` }}
            >
              {risk_score}
            </div>
            <div
              className="absolute -top-1.5 h-6 w-1 -translate-x-1/2 rounded-full border-2 border-white bg-slate-900 shadow dark:border-slate-900 dark:bg-white"
              style={{ left: `${risk_score}%` }}
            />
          </div>
          <div className="mt-4 grid grid-cols-3 gap-2 text-center text-xs">
            <div>
              <div className="font-semibold text-green-700 dark:text-green-400">Safe</div>
              <div className="text-slate-400">0–30</div>
            </div>
            <div>
              <div className="font-semibold text-amber-700 dark:text-amber-400">Suspicious</div>
              <div className="text-slate-400">31–60</div>
            </div>
            <div>
              <div className="font-semibold text-red-700 dark:text-red-400">Phishing</div>
              <div className="text-slate-400">61–100</div>
            </div>
          </div>
          <p className="mt-4 text-center text-xs text-slate-400">
            The score combines a model prediction with security heuristics; it is not a breakdown of individual score contributions.
          </p>
        </div>
      </ChartCard>

      {/* Bar: Feature Importance */}
      <ChartCard title="Top model signals" subtitle="Relative signal weights for this prediction (not score contributions)">
        {featureData.length > 0 ? (
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={featureData} layout="vertical" margin={{ left: 8, right: 16 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" horizontal={false} />
              <XAxis type="number" domain={[0, 100]} tick={{ fontSize: 10 }} unit="%" />
              <YAxis type="category" dataKey="name" width={150} tick={{ fontSize: 10 }} />
              <Tooltip
                formatter={(value: number) => [`${value}%`, 'Model importance']}
                contentStyle={{ background: '#1e293b', border: 'none', borderRadius: 12, fontSize: 12 }}
                labelStyle={{ color: '#94a3b8' }}
                itemStyle={{ color: '#f1f5f9' }}
              />
              <Bar dataKey="value" fill={color} radius={[0, 6, 6, 0]} animationDuration={1000} />
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <p className="py-16 text-center text-sm text-slate-400">
            Model signal weights are unavailable for this scan.
          </p>
        )}
      </ChartCard>
    </div>
  );
}

function ChartCard({ title, subtitle, children, className = '' }: {
  title: string; subtitle: string; children: React.ReactNode; className?: string;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className={`bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-700 p-5 shadow-card ${className}`}
    >
      <div className="mb-4">
        <h3 className="font-semibold text-slate-800 dark:text-white text-sm">{title}</h3>
        <p className="text-xs text-slate-400 dark:text-slate-500">{subtitle}</p>
      </div>
      {children}
    </motion.div>
  );
}
