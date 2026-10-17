import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Legend
} from 'recharts';
import { motion } from 'framer-motion';
import type { ScanResult } from '../../types';
import { getRiskColor } from '../../types';

interface Props { result: ScanResult; }

const COLORS = ['#22c55e', '#f59e0b', '#ef4444'];

export default function ChartsSection({ result }: Props) {
  const { reasons, risk_score } = result;

  // ── Pie: Risk Breakdown ────────────────────────────────────────
  const safe       = Math.max(0, 100 - risk_score);
  const pieData = [
    { name: 'Safe Score',     value: safe        },
    { name: 'Moderate Risk',  value: Math.min(risk_score, 40) },
    { name: 'High Risk',      value: Math.max(0, risk_score - 40) },
  ].filter(d => d.value > 0);

  // These weights are model feature importances, not score-point contributions.
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
      {/* Pie */}
      <ChartCard title="Risk Breakdown" subtitle="Score distribution">
        <ResponsiveContainer width="100%" height={220}>
          <PieChart>
            <Pie
              data={pieData}
              cx="50%" cy="50%"
              innerRadius={55}
              outerRadius={85}
              paddingAngle={3}
              dataKey="value"
              animationBegin={0}
              animationDuration={1000}
            >
              {pieData.map((_, i) => (
                <Cell key={i} fill={COLORS[i]} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{ background: '#1e293b', border: 'none', borderRadius: 12, fontSize: 12 }}
              labelStyle={{ color: '#94a3b8' }}
              itemStyle={{ color: '#f1f5f9' }}
            />
            <Legend
              iconType="circle"
              iconSize={8}
              wrapperStyle={{ fontSize: 12 }}
            />
          </PieChart>
        </ResponsiveContainer>
      </ChartCard>

      {/* Bar: Feature Importance */}
      <ChartCard title="Top model signals" subtitle="Relative importance for this prediction (not score points)">
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
