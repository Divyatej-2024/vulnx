import React, { useEffect, useState } from 'react';
import axios from 'axios';

function App() {
  const [vulns, setVulns] = useState([]);
  useEffect(() => {
    axios.get('http://localhost:8000/api/v1/vulns?limit=10')
      .then(res => setVulns(res.data.vulns))
      .catch(err => console.error(err));
  }, []);
  return (
    <div style={{ padding: 20 }}>
      <h1>VulnX — Top Vulnerabilities</h1>
      <table border="1" cellPadding="6">
        <thead><tr><th>CVE</th><th>CVSS v3</th><th>Published</th><th>Score</th></tr></thead>
        <tbody>
          {vulns.map(v => (
            <tr key={v.cve_id}>
              <td>{v.cve_id}</td>
              <td>{v.cvss_v3}</td>
              <td>{v.published_date}</td>
              <td>{(v.score || 0).toFixed(3)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default App;
