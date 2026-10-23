import { HelpCircle, Check, ShieldAlert, AlertTriangle, ShieldCheck } from 'lucide-react';
import type { AnalysisResult } from '../services/api';

interface ThreatExplanationProps {
  result: AnalysisResult;
}

export default function ThreatExplanation({ result }: ThreatExplanationProps) {
  const { classification, risk_score, ml_probability, indicators, recommendations, input_type, score_breakdown } = result;

  // 1. Generate checkmarked explanatory points based on indicators and scores
  const getExplanationPoints = (): string[] => {
    const points: string[] = [];

    if (indicators && indicators.length > 0) {
      indicators.forEach((ind) => {
        const lower = ind.toLowerCase();
        if (lower.includes('http') && !lower.includes('https')) {
          points.push('Suspicious or non-secure HTTP connection');
        } else if (lower.includes('brand') || lower.includes('impersonat')) {
          points.push('Brand impersonation detected');
        } else if (lower.includes('subdomain')) {
          points.push('Excessive subdomains in URL structure');
        } else if (lower.includes('tld') || lower.includes('top-level domain')) {
          points.push('Suspicious top-level domain extension');
        } else if (lower.includes('keyword') || lower.includes('login') || lower.includes('password')) {
          points.push('Login or credential-related keyword detected');
        } else if (lower.includes('ip address')) {
          points.push('Raw IP address used instead of domain name');
        } else if (lower.includes('shorten')) {
          points.push('URL shortening service detected');
        } else if (lower.includes('urgenc')) {
          points.push('Urgent or high-pressure language detected');
        } else if (lower.includes('credential') || lower.includes('identity')) {
          points.push('Credential harvesting pattern detected');
        } else if (lower.includes('otp') || lower.includes('verification code')) {
          points.push('OTP or verification code request');
        } else if (lower.includes('payment') || lower.includes('financial') || lower.includes('bank')) {
          points.push('Financial transaction or payment request');
        } else if (lower.includes('long url') || lower.includes('hyphen') || lower.includes('digit')) {
          points.push('Suspicious URL structure');
        } else if (lower.includes('social engineering')) {
          points.push('Social engineering tactics detected');
        } else {
          // Fallback clean formatting for any other indicator
          points.push(ind);
        }
      });
    }

    // Include ML model signal if probability is notable
    if (ml_probability >= 0.5) {
      points.push(`High ML model threat probability (${(ml_probability * 100).toFixed(1)}%)`);
    } else if (score_breakdown && score_breakdown.ml_component > 15) {
      points.push('ML feature anomaly detected');
    }

    // Deduplicate points
    const uniquePoints = Array.from(new Set(points));

    // Fallbacks for safe or low indicator results
    if (uniquePoints.length === 0) {
      if (classification === 'SAFE') {
        return [
          'No malicious URL or content indicators detected',
          'Standard domain structure and secure connection verified',
          'Low threat risk score from multi-layer evaluation',
        ];
      } else {
        return [
          'Suspicious pattern detected',
          `Elevated overall risk score (${risk_score}/100)`,
        ];
      }
    }

    return uniquePoints;
  };

  // 2. Infer Attack Type based on indicators and inputs
  const getAttackType = (): string => {
    const allText = (indicators || []).join(' ').toLowerCase();

    if (allText.includes('credential') || allText.includes('login') || allText.includes('password') || allText.includes('identity verification')) {
      return 'Credential Harvesting';
    }
    if (allText.includes('brand') || allText.includes('impersonat')) {
      return 'Brand Impersonation';
    }
    if (allText.includes('otp') || allText.includes('verification code')) {
      return 'OTP / Verification Code Theft';
    }
    if (allText.includes('payment') || allText.includes('financial') || allText.includes('bank') || allText.includes('prize')) {
      return 'Financial & Payment Scam';
    }
    if (allText.includes('urgenc') || allText.includes('suspension') || allText.includes('social engineering')) {
      return 'Social Engineering / Urgency Pressure';
    }
    if (allText.includes('download') || allText.includes('attachment')) {
      return 'Malware / Attachment Risk';
    }
    if (input_type === 'url' && (allText.includes('ip address') || allText.includes('subdomain') || allText.includes('tld') || allText.includes('http'))) {
      return 'Deceptive URL / Domain Spoofing';
    }
    if (classification === 'SAFE') {
      return 'Legitimate Content / Low Risk';
    }
    return 'Suspicious Phishing Vector';
  };

  // 3. Recommended Action
  const getRecommendedAction = (): string => {
    if (recommendations && recommendations.length > 0) {
      // Pick the most critical recommendation
      const critical = recommendations.find(r => r.toLowerCase().includes('credentials') || r.toLowerCase().includes('click') || r.toLowerCase().includes('payment'));
      if (critical) return `${critical}.`;
      return `${recommendations[0]}.`;
    }

    if (classification === 'PHISHING') {
      return 'Do not enter credentials or payment information.';
    } else if (classification === 'SUSPICIOUS') {
      return 'Exercise caution before interacting with links or sharing details.';
    } else {
      return 'Content appears safe. Remain vigilant for unverified communications.';
    }
  };

  const points = getExplanationPoints();
  const attackType = getAttackType();
  const recommendedAction = getRecommendedAction();

  const getStatusColor = () => {
    switch (classification) {
      case 'PHISHING': return 'var(--accent-red)';
      case 'SUSPICIOUS': return 'var(--accent-yellow)';
      case 'SAFE': return 'var(--accent-green)';
      default: return 'var(--accent-blue)';
    }
  };

  const statusColor = getStatusColor();

  return (
    <div className="glass-card animate-fade-in-up" style={{ padding: 28, marginTop: 20 }}>
      {/* Section Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20, paddingBottom: 16, borderBottom: '1px solid var(--border-subtle)' }}>
        <div style={{
          width: 36, height: 36, borderRadius: 10,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: `${statusColor}18`, color: statusColor,
        }}>
          <HelpCircle size={20} />
        </div>
        <div>
          <h4 style={{ fontSize: 16, fontWeight: 800, color: 'white', letterSpacing: '-0.01em' }}>
            WHY WAS THIS DETECTED?
          </h4>
          <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
            Transparent AI explanation breakdown for Scan #{result.scan_id}
          </p>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr', gap: 24 }}>
        {/* LEFT COLUMN: Checkmarked Reasons */}
        <div>
          <h5 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-secondary)', marginBottom: 12, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Key Detection Factors
          </h5>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {points.map((pt, idx) => (
              <div key={idx} style={{
                display: 'flex', alignItems: 'flex-start', gap: 10,
                fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.5,
              }}>
                <div style={{
                  width: 20, height: 20, borderRadius: '50%', flexShrink: 0,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  background: classification === 'SAFE' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                  color: classification === 'SAFE' ? 'var(--accent-green)' : 'var(--accent-red)',
                  marginTop: 1,
                }}>
                  <Check size={13} strokeWidth={3} />
                </div>
                <span>{pt}</span>
              </div>
            ))}
          </div>
        </div>

        {/* RIGHT COLUMN: Attack Type & Recommended Action */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Attack Type Card */}
          <div style={{
            padding: '16px 18px', borderRadius: 12,
            background: 'var(--bg-primary)', border: '1px solid var(--border-color)',
          }}>
            <p style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>
              Attack Type
            </p>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              {classification === 'PHISHING' ? (
                <ShieldAlert size={16} color="var(--accent-red)" />
              ) : classification === 'SUSPICIOUS' ? (
                <AlertTriangle size={16} color="var(--accent-yellow)" />
              ) : (
                <ShieldCheck size={16} color="var(--accent-green)" />
              )}
              <span style={{ fontSize: 14, fontWeight: 700, color: 'white' }}>
                {attackType}
              </span>
            </div>
          </div>

          {/* Recommended Action Card */}
          <div style={{
            padding: '16px 18px', borderRadius: 12,
            background: classification === 'PHISHING'
              ? 'rgba(239, 68, 68, 0.08)'
              : classification === 'SUSPICIOUS'
              ? 'rgba(245, 158, 11, 0.08)'
              : 'rgba(16, 185, 129, 0.08)',
            border: `1px solid ${statusColor}25`,
          }}>
            <p style={{ fontSize: 11, fontWeight: 700, color: statusColor, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>
              Recommended Action
            </p>
            <p style={{ fontSize: 13, color: 'var(--text-primary)', fontWeight: 600, lineHeight: 1.5 }}>
              {recommendedAction}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
