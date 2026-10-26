import React from 'react';

export default function PrivacyNotice({ onClose, onAcknowledge, firstVisit }) {
  const finish = firstVisit ? onAcknowledge : onClose;
  const policyPath = (process.env.PUBLIC_URL || '') + '/privacy.html';

  return (
    <div className="privacy-backdrop" role="presentation">
      <section className="privacy-dialog" role="dialog" aria-modal="true" aria-labelledby="privacy-title" aria-describedby="privacy-intro">
        <div className="privacy-mark" aria-hidden="true">V</div>
        <p className="privacy-eyebrow">PRIVACY &amp; SECURITY</p>
        <h2 id="privacy-title">{firstVisit ? 'Before you use VulnX' : 'Privacy & consent'}</h2>
        <p id="privacy-intro" className="privacy-intro">VulnX helps you explore publicly available vulnerability information. Here is what to know about data and your device.</p>
        <div className="privacy-points">
          <article><strong>Public vulnerability data</strong><p>The dashboard requests CVE information from the VulnX API. The current app does not offer user accounts.</p></article>
          <article><strong>Local storage and cache</strong><p>The app may cache its app shell and recently loaded public vulnerability responses in your browser to support faster loading and limited offline access.</p></article>
          <article><strong>Technical service logs</strong><p>Hosting and delivery providers may process technical request information, such as IP addresses and timestamps, to deliver and protect the service. Their own policies apply.</p></article>
          <article><strong>No optional tracking currently enabled</strong><p>The current frontend does not intentionally use advertising or analytics SDKs and does not request location, contacts, camera, or microphone access. This notice is an acknowledgement, not consent to optional tracking.</p></article>
        </div>
        <p className="privacy-policy-link">Read the full <a href={policyPath} target="_blank" rel="noopener noreferrer">VulnX Privacy Policy</a>.</p>
        <div className="privacy-actions">
          {!firstVisit && <button type="button" className="privacy-secondary" onClick={onClose}>Close</button>}
          <button type="button" className="privacy-primary" onClick={finish}>{firstVisit ? 'I understand — continue' : 'Done'}</button>
        </div>
        <p className="privacy-footnote">You can reopen this notice from the sidebar at any time.</p>
      </section>
    </div>
  );
}
