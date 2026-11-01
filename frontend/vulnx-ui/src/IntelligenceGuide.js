import React, { useState } from 'react';
import './IntelligenceGuide.css';

const concepts = [
  {
    term: 'CVSS — How serious could it be?',
    explanation: 'A technical severity score from 0 to 10. It describes the potential impact and characteristics of a vulnerability. A high CVSS score does not, by itself, mean attackers are using it.',
    example: 'Think of CVSS as the size of the potential problem.'
  },
  {
    term: 'EPSS — How likely is exploitation?',
    explanation: 'A probability from 0% to 100% estimating the chance that a vulnerability will be exploited in the wild over the next 30 days. It is a model estimate, not a guarantee.',
    example: 'Think of EPSS as a weather forecast: useful for planning, never certain.'
  },
  {
    term: 'CISA KEV — Is exploitation confirmed?',
    explanation: 'The Known Exploited Vulnerabilities catalogue identifies vulnerabilities that CISA says have been exploited in the wild. A match is a strong reason to investigate and prioritise remediation.',
    example: 'Think of KEV as a confirmed warning, not just a prediction.'
  },
  {
    term: 'VulnX priority — What should I review first?',
    explanation: 'A transparent 0–100 sorting aid that combines CVSS, EPSS and KEV membership. It helps compare records; it is not a breach probability, a replacement for professional assessment, or an AI prediction.',
    example: 'Use it to organise investigation, then check whether the affected product exists in your environment.'
  }
];

function IntelligenceGuide() {
  const [expanded, setExpanded] = useState(false);

  return (
    <section className="intelligence-guide" aria-labelledby="guide-title">
      <div className="guide-intro">
        <div className="guide-icon" aria-hidden="true">?</div>
        <div className="guide-copy">
          <div className="eyebrow">NEW TO VULNX?</div>
          <h2 id="guide-title">Turn vulnerability data into a clear next step.</h2>
          <p>VulnX brings public security information together. You use it to decide which vulnerabilities deserve a closer look — not to assume that every listed issue affects your systems.</p>
        </div>
        <button
          className="guide-toggle"
          type="button"
          aria-expanded={expanded}
          aria-controls="guide-details"
          onClick={() => setExpanded((current) => !current)}
        >
          {expanded ? 'Hide guide' : 'Explain the numbers'}
          <span aria-hidden="true">{expanded ? '−' : '+'}</span>
        </button>
      </div>

      <div className="guide-steps" aria-label="How to use VulnX">
        <div><span>01</span><strong>Find</strong><small>Search by CVE ID or keyword.</small></div>
        <div><span>02</span><strong>Understand</strong><small>Read severity and threat evidence.</small></div>
        <div><span>03</span><strong>Prioritise</strong><small>Review KEV, EPSS and the priority score.</small></div>
        <div><span>04</span><strong>Act</strong><small>Check your assets and follow vendor guidance.</small></div>
      </div>

      {expanded && (
        <div className="guide-details" id="guide-details">
          <h3>What each number actually means</h3>
          <div className="guide-concepts">
            {concepts.map((concept) => (
              <article key={concept.term} className="guide-concept">
                <h4>{concept.term}</h4>
                <p>{concept.explanation}</p>
                <small>{concept.example}</small>
              </article>
            ))}
          </div>
          <p className="guide-caution"><strong>Important:</strong> VulnX currently analyses public vulnerability records. It does not scan your network, identify your installed software, confirm that you are exposed, or patch devices. Verify asset exposure with your own inventory and security tools.</p>
        </div>
      )}
    </section>
  );
}

export default IntelligenceGuide;
