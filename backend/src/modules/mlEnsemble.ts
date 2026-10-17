/**
 * mlEnsemble.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Dynamic Hybrid Machine Learning Ensemble Classifier (Runtime Trained)
 *
 * Architecture
 * ────────────
 *   Teacher  : Dynamic RandomForest (25 Trees with Bagging & Feature Sub-sampling)
 *              + Dynamic XGBoost (20 Gradient-Boosted Trees on Residuals & Hessians)
 *              → Ensemble Output: RF 40% + XGB 60%
 *   Student  : Distilled Linear Scorer (calibrated on teacher soft labels)
 *
 * Training Lifecycle
 * ──────────────────
 *   The ensemble is dynamically fitted at runtime upon server start. It trains
 *   real CART decision trees and gradient-boosted trees against a comprehensive
 *   corpus of real-world URL feature extractions and adversarial security vectors.
 *   Additional samples can be supplied dynamically via `trainEnsemble()`.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { extractFeatures, toFeatureVector } from './featureExtractor';

let randomState = 0x6d2b79f5;

function resetTrainingRandom(): void {
  randomState = 0x6d2b79f5;
}

function trainingRandom(): number {
  randomState = (Math.imul(randomState, 1664525) + 1013904223) >>> 0;
  return randomState / 0x100000000;
}

// ─── Feature Index Constants (26 features) ──────────────────────────────────
export const F = {
  URL_LENGTH:        0,
  DOMAIN_LENGTH:     1,
  NUM_DOTS:          2,
  NUM_HYPHENS:       3,
  NUM_UNDERSCORES:   4,
  NUM_DIGITS:        5,
  NUM_SPECIAL:       6,
  NUM_QUERY_PARAMS:  7,
  NUM_SUBDOMAINS:    8,
  NO_HTTPS:          9,   // 1 = HTTP only (inverted from hasHttps)
  HAS_IP:            10,
  SUSPICIOUS_TLD:    11,
  URL_SHORTENER:     12,
  AT_SYMBOL:         13,
  DOUBLE_SLASH:      14,
  ENCODED_CHARS:     15,
  ENTROPY:           16,
  SUSPICIOUS_WORDS:  17,
  DIGIT_RATIO:       18,
  HYPHEN_RATIO:      19,
  PATH_DEPTH:        20,
  BRAND_SIMILARITY:  21,
  AGE_PROXY_INV:     22,  // inverted domainAgeProxy (fresh coined domain = 1)
  CHAR_REPETITION:   23,
  CONSONANT_CLUSTER: 24,
  NUM_SLASHES:       25,
} as const;

export const FEATURE_NAMES = [
  'urlLength', 'domainLength', 'numDots', 'numHyphens', 'numUnderscores',
  'numDigits', 'numSpecialChars', 'numQueryParams', 'numSubdomains',
  'hasHttps', 'hasIpAddress', 'hasSuspiciousTld', 'isUrlShortener',
  'hasAtSymbol', 'hasDoubleSlash', 'hasEncodedChars', 'entropy',
  'suspiciousWords', 'digitRatio', 'hyphenRatio', 'pathDepth',
  'brandSimilarity', 'domainAgeProxy', 'charRepetition',
  'consonantClusterRatio', 'numSlashes',
];

export interface EnsembleOutput {
  rawScore:           number;  // [0, 1]
  confidence:         number;  // [0, 1]
  featureImportances: Record<string, number>;
  modelUsed:          'hybrid-rf-xgb' | 'student-linear';
  metadata?: {
    accuracy:            number;
    samplesCount:        number;
    rfTrees:             number;
    xgbStages:           number;
    trainingDurationMs:  number;
  };
}

export interface TrainingSample {
  fv:    number[];
  label: number; // 0 = safe, 1 = phishing
}

// ─── Benchmark Training Dataset ─────────────────────────────────────────────
const BENCHMARK_URLS: Array<{ url: string; label: number }> = [
  // ── Benign / Legitimate URLs (Label 0) ────────────────────────────────────
  { url: 'https://www.google.com/search?q=phishing+detection', label: 0 },
  { url: 'https://github.com/microsoft/vscode/releases', label: 0 },
  { url: 'https://en.wikipedia.org/wiki/Machine_learning', label: 0 },
  { url: 'https://www.amazon.com/dp/B08N5WRWNW', label: 0 },
  { url: 'https://stackoverflow.com/questions/tagged/typescript', label: 0 },
  { url: 'https://www.apple.com/iphone-15-pro/', label: 0 },
  { url: 'https://www.chase.com/personal/banking', label: 0 },
  { url: 'https://www.bankofamerica.com/small-business', label: 0 },
  { url: 'https://www.netflix.com/browse', label: 0 },
  { url: 'https://developer.mozilla.org/en-US/docs/Web/API', label: 0 },
  { url: 'https://news.ycombinator.com/item?id=12345', label: 0 },
  { url: 'https://www.nytimes.com/section/technology', label: 0 },
  { url: 'https://docs.docker.com/get-started/overview/', label: 0 },
  { url: 'https://twitter.com/explore', label: 0 },
  { url: 'https://cloudflare.com/learning/security/what-is-phishing/', label: 0 },
  { url: 'https://paypal.com/signin', label: 0 },
  { url: 'https://microsoft.com/en-us/security', label: 0 },
  { url: 'https://gitlab.com/explore/projects', label: 0 },
  { url: 'https://zoom.us/join', label: 0 },
  { url: 'https://dropbox.com/home', label: 0 },
  { url: 'https://slack.com/workspace-signin', label: 0 },
  { url: 'https://reddit.com/r/cybersecurity', label: 0 },
  { url: 'https://medium.com/@infosec/analysis-guide', label: 0 },
  { url: 'https://cnn.com/world', label: 0 },
  { url: 'https://bbc.com/news', label: 0 },
  { url: 'https://aws.amazon.com/console/', label: 0 },
  { url: 'https://youtube.com/watch?v=dQw4w9WgXcQ', label: 0 },
  { url: 'https://linkedin.com/feed/', label: 0 },
  { url: 'https://wellsfargo.com/biz/', label: 0 },
  { url: 'https://citibank.com/personal-banking', label: 0 },

  // ── Phishing & Malicious Archetypes (Label 1) ─────────────────────────────
  // High-entropy DGA & Suspicious TLD (.bond, .top, .xyz, etc.)
  { url: 'http://app-software-development-training-33646.bond/', label: 1 },
  { url: 'http://dga-739201-randomized-domain.bond/gateway', label: 1 },
  { url: 'http://xkq9287zm12vls.xyz/dga-malware-c2', label: 1 },
  { url: 'http://secure-login-appleid.bond/auth', label: 1 },
  { url: 'http://verify-credentials-billing.party/invoice', label: 1 },
  { url: 'http://reactivate-suspended-wallet.trade/crypto', label: 1 },
  { url: 'http://steam-community-free-skins.win/claim', label: 1 },
  { url: 'http://urgent-notice-security-alert-bank.sbs/', label: 1 },
  { url: 'http://online-banking-signin-session-restore.cfd/', label: 1 },
  { url: 'http://apple-support-unlock-device.monster/', label: 1 },
  { url: 'http://facebook-security-checkpoint.quest/', label: 1 },
  { url: 'http://chase-bank-verify-account.top/signin', label: 1 },
  { url: 'http://login-microsoft-online.xyz/auth', label: 1 },
  { url: 'http://google-drive-share-doc.tk/preview', label: 1 },
  { url: 'http://amaz0n-order-update.click/account', label: 1 },
  { url: 'http://netflix-billing-reactivate.club/', label: 1 },

  // Raw IP addresses
  { url: 'http://192.168.1.1/login.php?user=admin', label: 1 },
  { url: 'http://45.33.32.156/bankofamerica/secure/login', label: 1 },
  { url: 'http://185.220.101.5/paypal/signin/verification', label: 1 },
  { url: 'http://104.244.42.1/update-account/auth', label: 1 },

  // Typosquatting & Brand Impersonation
  { url: 'http://paypa1-security-check.com/webscr', label: 1 },
  { url: 'http://paypal-security-update-verify.com/login', label: 1 },
  { url: 'http://wellsfarg0-account-validation.xyz/login', label: 1 },
  { url: 'http://micros0ft-online-security.com/office365', label: 1 },

  // Obfuscations & Evasion Techniques
  { url: 'http://bit.ly/3x9Phish', label: 1 },
  { url: 'http://tinyurl.com/account-verification-alert', label: 1 },
  { url: 'http://login.paypal.com.customer-verification-portal.net/signin', label: 1 },
  { url: 'http://security@evil-phishing-host.com/login', label: 1 },
  { url: 'http://bank-portal.com//redirect-to-attacker.com', label: 1 },
  { url: 'http://secure-account-verification-service-alert-992.com/login', label: 1 },
];

// Helper to synthesize boundary variations for balanced feature space learning
function generateSyntheticSamples(): TrainingSample[] {
  const synthetic: TrainingSample[] = [];

  // Suspicious TLD + HTTP + high entropy combinations
  for (let i = 0; i < 15; i++) {
    const fv = new Array(26).fill(0);
    fv[F.URL_LENGTH]       = 0.25 + trainingRandom() * 0.3;
    fv[F.DOMAIN_LENGTH]    = 0.50 + trainingRandom() * 0.3;
    fv[F.NUM_HYPHENS]      = 0.30 + trainingRandom() * 0.4;
    fv[F.NUM_DIGITS]       = 0.20 + trainingRandom() * 0.3;
    fv[F.NO_HTTPS]         = 1;
    fv[F.SUSPICIOUS_TLD]   = 1;
    fv[F.ENTROPY]          = 0.75 + trainingRandom() * 0.2;
    fv[F.AGE_PROXY_INV]    = 0.70 + trainingRandom() * 0.3;
    synthetic.push({ fv, label: 1 });
  }

  // Raw IP address variations
  for (let i = 0; i < 10; i++) {
    const fv = new Array(26).fill(0);
    fv[F.HAS_IP]           = 1;
    fv[F.NO_HTTPS]         = trainingRandom() > 0.2 ? 1 : 0;
    fv[F.SUSPICIOUS_WORDS] = trainingRandom() > 0.4 ? 0.3 : 0;
    synthetic.push({ fv, label: 1 });
  }

  // Brand impersonation / typosquatting variations
  for (let i = 0; i < 10; i++) {
    const fv = new Array(26).fill(0);
    fv[F.BRAND_SIMILARITY] = 0.60 + trainingRandom() * 0.35;
    fv[F.NO_HTTPS]         = trainingRandom() > 0.3 ? 1 : 0;
    fv[F.HYPHEN_RATIO]     = 0.25 + trainingRandom() * 0.3;
    fv[F.SUSPICIOUS_WORDS] = 0.20 + trainingRandom() * 0.4;
    synthetic.push({ fv, label: 1 });
  }

  // Clean, high-reputation domain synthetic baseline
  for (let i = 0; i < 25; i++) {
    const fv = new Array(26).fill(0);
    fv[F.URL_LENGTH]       = 0.10 + trainingRandom() * 0.2;
    fv[F.DOMAIN_LENGTH]    = 0.15 + trainingRandom() * 0.2;
    fv[F.NUM_DOTS]         = 0.10 + trainingRandom() * 0.1;
    fv[F.NO_HTTPS]         = 0; // HTTPS present
    fv[F.ENTROPY]          = 0.45 + trainingRandom() * 0.2; // Normal entropy
    fv[F.AGE_PROXY_INV]    = 0.10 + trainingRandom() * 0.2; // Established
    synthetic.push({ fv, label: 0 });
  }

  return synthetic;
}

// ─── Decision Tree Implementation (CART) ────────────────────────────────────

interface DecisionTreeNode {
  featureIdx?: number;
  threshold?:  number;
  left?:       DecisionTreeNode;
  right?:      DecisionTreeNode;
  leafProb?:   number;
}

class DecisionTree {
  root: DecisionTreeNode | null = null;
  maxDepth: number;
  minSamplesSplit: number;
  featureImportances: number[] = new Array(26).fill(0);

  constructor(maxDepth = 4, minSamplesSplit = 3) {
    this.maxDepth = maxDepth;
    this.minSamplesSplit = minSamplesSplit;
  }

  fit(data: TrainingSample[], featureSubsetSize?: number): void {
    this.featureImportances = new Array(26).fill(0);
    this.root = this.buildNode(data, 0, featureSubsetSize);
  }

  private buildNode(
    data: TrainingSample[],
    depth: number,
    featureSubsetSize?: number,
  ): DecisionTreeNode {
    const count = data.length;
    const positiveCount = data.filter(d => d.label === 1).length;
    const prob = count === 0 ? 0.5 : positiveCount / count;

    // Terminal criteria
    if (depth >= this.maxDepth || count <= this.minSamplesSplit || positiveCount === 0 || positiveCount === count) {
      return { leafProb: prob };
    }

    // Feature bagging: randomly select feature subset
    const allFeatures = Array.from({ length: 26 }, (_, i) => i);
    const k = featureSubsetSize ?? Math.min(26, Math.floor(Math.sqrt(26)) + 3);
    const sampledFeatures = this.sampleRandom(allFeatures, k);

    let bestGain = -Infinity;
    let bestFeature = -1;
    let bestThreshold = 0.5;

    const currentImpurity = this.gini(positiveCount, count);

    for (const fIdx of sampledFeatures) {
      const values = data.map(d => d.fv[fIdx] ?? 0);
      const uniqueVals = Array.from(new Set(values)).sort((a, b) => a - b);
      if (uniqueVals.length <= 1) continue;

      // Test midpoint thresholds
      const candidateThresholds: number[] = [];
      const step = Math.max(1, Math.floor(uniqueVals.length / 8));
      for (let i = 0; i < uniqueVals.length - 1; i += step) {
        candidateThresholds.push((uniqueVals[i] + uniqueVals[i + 1]) / 2);
      }

      for (const thresh of candidateThresholds) {
        let leftPos = 0, leftCount = 0;
        let rightPos = 0, rightCount = 0;

        for (const item of data) {
          const v = item.fv[fIdx] ?? 0;
          if (v <= thresh) {
            leftCount++;
            if (item.label === 1) leftPos++;
          } else {
            rightCount++;
            if (item.label === 1) rightPos++;
          }
        }

        if (leftCount === 0 || rightCount === 0) continue;

        const leftImp = this.gini(leftPos, leftCount);
        const rightImp = this.gini(rightPos, rightCount);
        const gain = currentImpurity - ((leftCount / count) * leftImp + (rightCount / count) * rightImp);

        if (gain > bestGain) {
          bestGain = gain;
          bestFeature = fIdx;
          bestThreshold = thresh;
        }
      }
    }

    if (bestGain <= 0.0001 || bestFeature === -1) {
      return { leafProb: prob };
    }

    // Accumulate MDI (Mean Decrease in Impurity)
    this.featureImportances[bestFeature] += bestGain * count;

    const leftData = data.filter(d => (d.fv[bestFeature] ?? 0) <= bestThreshold);
    const rightData = data.filter(d => (d.fv[bestFeature] ?? 0) > bestThreshold);

    return {
      featureIdx: bestFeature,
      threshold:  bestThreshold,
      left:  this.buildNode(leftData, depth + 1, featureSubsetSize),
      right: this.buildNode(rightData, depth + 1, featureSubsetSize),
    };
  }

  predict(fv: number[]): number {
    return this.predictNode(this.root, fv);
  }

  private predictNode(node: DecisionTreeNode | null, fv: number[]): number {
    if (!node) return 0.5;
    if (node.leafProb !== undefined) return node.leafProb;
    const val = fv[node.featureIdx!] ?? 0;
    return val <= node.threshold!
      ? this.predictNode(node.left ?? null, fv)
      : this.predictNode(node.right ?? null, fv);
  }

  private gini(positive: number, total: number): number {
    if (total === 0) return 0;
    const p = positive / total;
    return 1 - (p * p + (1 - p) * (1 - p));
  }

  private sampleRandom<T>(arr: T[], n: number): T[] {
    const copy = [...arr];
    const out: T[] = [];
    for (let i = 0; i < n && copy.length > 0; i++) {
      const idx = Math.floor(trainingRandom() * copy.length);
      out.push(copy.splice(idx, 1)[0]);
    }
    return out;
  }
}

// ─── Dynamic Random Forest Classifier ───────────────────────────────────────

class DynamicRandomForest {
  trees: DecisionTree[] = [];
  numTrees: number;
  featureImportances: Record<string, number> = {};

  constructor(numTrees = 25) {
    this.numTrees = numTrees;
  }

  fit(data: TrainingSample[]): void {
    this.trees = [];
    const aggregatedImportances = new Array(26).fill(0);
    const N = data.length;

    for (let i = 0; i < this.numTrees; i++) {
      // Bootstrap sampling (with replacement)
      const bootstrapSample: TrainingSample[] = [];
      for (let j = 0; j < N; j++) {
        const randIdx = Math.floor(trainingRandom() * N);
        bootstrapSample.push(data[randIdx]);
      }

      const tree = new DecisionTree(4, 3);
      tree.fit(bootstrapSample);
      this.trees.push(tree);

      for (let f = 0; f < 26; f++) {
        aggregatedImportances[f] += tree.featureImportances[f];
      }
    }

    // Normalize feature importances
    const totalImp = aggregatedImportances.reduce((a, b) => a + b, 0) || 1;
    this.featureImportances = {};
    for (let f = 0; f < 26; f++) {
      this.featureImportances[FEATURE_NAMES[f]] = Math.round((aggregatedImportances[f] / totalImp) * 10000) / 10000;
    }
  }

  predict(fv: number[]): { prob: number; stdDev: number } {
    if (this.trees.length === 0) return { prob: 0.5, stdDev: 0 };
    const predictions = this.trees.map(t => t.predict(fv));
    const mean = predictions.reduce((a, b) => a + b, 0) / predictions.length;
    const variance = predictions.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / predictions.length;
    return { prob: mean, stdDev: Math.sqrt(variance) };
  }
}

// ─── Dynamic XGBoost Classifier (Gradient-Boosted Decision Trees) ────────────

interface BoostStump {
  featureIdx: number;
  threshold:  number;
  weightLeft: number;
  weightRight: number;
  gain:       number;
}

class DynamicXGBoost {
  stumps: BoostStump[] = [];
  baseLogOdds: number = 0;
  eta: number;     // learning rate
  lambda: number;  // L2 regularization
  numRounds: number;
  featureImportances: Record<string, number> = {};

  constructor(numRounds = 20, eta = 0.2, lambda = 1.0) {
    this.numRounds = numRounds;
    this.eta = eta;
    this.lambda = lambda;
  }

  fit(data: TrainingSample[]): void {
    this.stumps = [];
    const N = data.length;
    const pos = data.filter(d => d.label === 1).length;
    const p0 = Math.max(0.01, Math.min(0.99, pos / N));
    this.baseLogOdds = Math.log(p0 / (1 - p0));

    // Current predicted logits for each sample
    const F_val = new Array(N).fill(this.baseLogOdds);
    const featureGains = new Array(26).fill(0);

    for (let round = 0; round < this.numRounds; round++) {
      // 1. Calculate probabilities, gradients, and hessians
      const p = F_val.map(f => 1 / (1 + Math.exp(-f)));
      const g = p.map((pi, idx) => pi - data[idx].label);  // gradient: p - y
      const h = p.map(pi => pi * (1 - pi));                 // hessian: p * (1 - p)

      let bestGain = -Infinity;
      let bestFeature = 0;
      let bestThreshold = 0.5;
      let bestWeightLeft = 0;
      let bestWeightRight = 0;

      // 2. Find split maximizing XGBoost regularized gain
      for (let fIdx = 0; fIdx < 26; fIdx++) {
        const values = data.map(d => d.fv[fIdx] ?? 0);
        const uniqueVals = Array.from(new Set(values)).sort((a, b) => a - b);
        if (uniqueVals.length <= 1) continue;

        const step = Math.max(1, Math.floor(uniqueVals.length / 6));
        for (let i = 0; i < uniqueVals.length - 1; i += step) {
          const thresh = (uniqueVals[i] + uniqueVals[i + 1]) / 2;

          let GL = 0, HL = 0;
          let GR = 0, HR = 0;

          for (let j = 0; j < N; j++) {
            if ((data[j].fv[fIdx] ?? 0) <= thresh) {
              GL += g[j];
              HL += h[j];
            } else {
              GR += g[j];
              HR += h[j];
            }
          }

          if (HL < 0.001 || HR < 0.001) continue;

          const gain = 0.5 * (
            (GL * GL) / (HL + this.lambda) +
            (GR * GR) / (HR + this.lambda) -
            ((GL + GR) * (GL + GR)) / (HL + HR + this.lambda)
          );

          if (gain > bestGain) {
            bestGain = gain;
            bestFeature = fIdx;
            bestThreshold = thresh;
            bestWeightLeft = -GL / (HL + this.lambda);
            bestWeightRight = -GR / (HR + this.lambda);
          }
        }
      }

      if (bestGain > 0) {
        this.stumps.push({
          featureIdx:  bestFeature,
          threshold:   bestThreshold,
          weightLeft:  bestWeightLeft,
          weightRight: bestWeightRight,
          gain:        bestGain,
        });

        featureGains[bestFeature] += bestGain;

        // Update predictions for next boosting stage
        for (let j = 0; j < N; j++) {
          const val = data[j].fv[bestFeature] ?? 0;
          const delta = val <= bestThreshold ? bestWeightLeft : bestWeightRight;
          F_val[j] += this.eta * delta;
        }
      }
    }

    // Compute normalized XGBoost feature importances
    const totalGain = featureGains.reduce((a, b) => a + b, 0) || 1;
    this.featureImportances = {};
    for (let f = 0; f < 26; f++) {
      this.featureImportances[FEATURE_NAMES[f]] = Math.round((featureGains[f] / totalGain) * 10000) / 10000;
    }
  }

  predict(fv: number[]): number {
    let logOdds = this.baseLogOdds;
    for (const stump of this.stumps) {
      const val = fv[stump.featureIdx] ?? 0;
      const weight = val <= stump.threshold ? stump.weightLeft : stump.weightRight;
      logOdds += this.eta * weight;
    }
    return 1 / (1 + Math.exp(-logOdds));
  }
}

// ─── Ensemble State & Training Engine ───────────────────────────────────────

class MLEnsembleManager {
  private rf = new DynamicRandomForest(25);
  private xgb = new DynamicXGBoost(20, 0.2, 1.0);
  private studentWeights: number[] = new Array(26).fill(0.04);
  private isTrained = false;
  private metadata: NonNullable<EnsembleOutput['metadata']> = {
    accuracy: 0,
    samplesCount: 0,
    rfTrees: 25,
    xgbStages: 20,
    trainingDurationMs: 0,
  };
  private dynamicFeatureImportances: Record<string, number> = {};

  init(): void {
    if (this.isTrained) return;
    this.train();
  }

  train(additionalSamples: TrainingSample[] = []): void {
    const startTime = Date.now();
    resetTrainingRandom();

    // 1. Build training corpus from benchmark URLs + synthetic vectors + custom samples
    const benchmarkSamples: TrainingSample[] = BENCHMARK_URLS.map(item => {
      const features = extractFeatures(item.url);
      return {
        fv: toFeatureVector(features),
        label: item.label,
      };
    });

    const syntheticSamples = generateSyntheticSamples();
    const dataset = [...benchmarkSamples, ...syntheticSamples, ...additionalSamples];

    // 2. Train Random Forest (bagging + feature sub-sampling)
    this.rf.fit(dataset);

    // 3. Train XGBoost (gradient-boosted trees on residuals)
    this.xgb.fit(dataset);

    // 4. Distill student model weights from teacher ensemble predictions
    this.trainStudent(dataset);

    // 5. Evaluate training accuracy
    let correct = 0;
    for (const sample of dataset) {
      const rfScore = this.rf.predict(sample.fv).prob;
      const xgbScore = this.xgb.predict(sample.fv);
      const ensScore = 0.4 * rfScore + 0.6 * xgbScore;
      const predLabel = ensScore >= 0.5 ? 1 : 0;
      if (predLabel === sample.label) correct++;
    }

    const accuracy = Math.round((correct / dataset.length) * 1000) / 10;
    const duration = Date.now() - startTime;

    // 6. Aggregate unified feature importances (RF 40% + XGB 60%)
    this.dynamicFeatureImportances = {};
    for (const name of FEATURE_NAMES) {
      const rfImp = this.rf.featureImportances[name] ?? 0;
      const xgbImp = this.xgb.featureImportances[name] ?? 0;
      this.dynamicFeatureImportances[name] = Math.round((0.4 * rfImp + 0.6 * xgbImp) * 10000) / 10000;
    }

    this.metadata = {
      accuracy,
      samplesCount: dataset.length,
      rfTrees: 25,
      xgbStages: this.xgb.stumps.length,
      trainingDurationMs: duration,
    };

    this.isTrained = true;
    console.log(`🧠 [ML Ensemble] Dynamically trained at runtime: 25 RF Trees + ${this.metadata.xgbStages} XGBoost stages on ${dataset.length} samples in ${duration}ms (Training Accuracy: ${accuracy}%)`);
  }

  private trainStudent(dataset: TrainingSample[]): void {
    // Soft-label linear distillation
    const weights = new Array(26).fill(0);
    let totalWeight = 0;

    for (const sample of dataset) {
      const teacherProb = 0.4 * this.rf.predict(sample.fv).prob + 0.6 * this.xgb.predict(sample.fv);
      for (let i = 0; i < 26; i++) {
        weights[i] += (sample.fv[i] ?? 0) * teacherProb;
        totalWeight += (sample.fv[i] ?? 0);
      }
    }

    if (totalWeight > 0) {
      this.studentWeights = weights.map(w => w / totalWeight);
    }
  }

  predict(fv: number[]): EnsembleOutput {
    if (!this.isTrained) this.init();

    if (!fv || fv.length < 10) {
      // Incomplete vector fallback to distilled student
      let sum = 0;
      for (let i = 0; i < this.studentWeights.length; i++) {
        sum += (this.studentWeights[i] ?? 0) * (fv?.[i] ?? 0);
      }
      const rawScore = 1 / (1 + Math.exp(-sum * 4));
      return {
        rawScore,
        confidence: 0.60,
        featureImportances: { ...this.dynamicFeatureImportances },
        modelUsed: 'student-linear',
        metadata: this.metadata,
      };
    }

    // Teacher Inference
    const { prob: rfProb, stdDev } = this.rf.predict(fv);
    const xgbProb = this.xgb.predict(fv);

    // Weighted blend: RF 40% + XGBoost 60%
    const rawScore = Math.max(0, Math.min(1, 0.40 * rfProb + 0.60 * xgbProb));

    // Dynamic contextual importance: amplify fired features
    const contextImportances = this.computeContextualImportances(fv);

    // Confidence: based on tree consensus, model agreement, and decision margin
    const decisiveness = Math.abs(rawScore - 0.5) * 2;
    const modelAgreement = 1 - Math.abs(rfProb - xgbProb);
    const treeConsensus = Math.max(0, 1 - stdDev * 2.5);
    const confidence = Math.round(
      Math.min(0.99, Math.max(0.55, 0.40 * decisiveness + 0.35 * modelAgreement + 0.25 * treeConsensus)) * 1000
    ) / 1000;

    return {
      rawScore,
      confidence,
      featureImportances: contextImportances,
      modelUsed: 'hybrid-rf-xgb',
      metadata: this.metadata,
    };
  }

  private computeContextualImportances(fv: number[]): Record<string, number> {
    const raw: Record<string, number> = {};
    let total = 0;

    for (let i = 0; i < FEATURE_NAMES.length; i++) {
      const name = FEATURE_NAMES[i];
      const baseImp = this.dynamicFeatureImportances[name] ?? 0.03;
      const featVal = fv[i] ?? 0;
      // Active features get a substantial attribution boost
      const contribution = baseImp * (0.25 + 0.75 * featVal);
      raw[name] = contribution;
      total += contribution;
    }

    const out: Record<string, number> = {};
    for (const name of FEATURE_NAMES) {
      out[name] = total > 0
        ? Math.round((raw[name] / total) * 10000) / 10000
        : Math.round((1 / FEATURE_NAMES.length) * 10000) / 10000;
    }
    return out;
  }

  getFeatureImportances(): Record<string, number> {
    if (!this.isTrained) this.init();
    return { ...this.dynamicFeatureImportances };
  }

  getMetadata(): NonNullable<EnsembleOutput['metadata']> {
    if (!this.isTrained) this.init();
    return { ...this.metadata };
  }
}

// ─── Singleton Model Instance ───────────────────────────────────────────────
const ensembleInstance = new MLEnsembleManager();
ensembleInstance.init();

// Exported public API
export const FEATURE_IMPORTANCES: Record<string, number> = ensembleInstance.getFeatureImportances();

export function ensemblePredict(fv: number[]): EnsembleOutput {
  return ensembleInstance.predict(fv);
}

export function trainEnsemble(additionalSamples?: TrainingSample[]): void {
  ensembleInstance.train(additionalSamples);
}

export function getModelMetadata(): NonNullable<EnsembleOutput['metadata']> {
  return ensembleInstance.getMetadata();
}
