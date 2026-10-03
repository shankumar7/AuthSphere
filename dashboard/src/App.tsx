import React, { useState, useEffect } from 'react';

export default function App() {
  const [stats, setStats] = useState({ active_entities: 1, pending: 0, revoked: 0, rotations_24h: 1 });

  return (
    <div style={{ padding: '32px', maxWidth: '1000px', margin: '0 auto' }}>
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px', borderBottom: '1px solid #334155', paddingBottom: '16px' }}>
        <div>
          <h1 style={{ color: '#38bdf8', margin: 0, fontSize: '28px' }}>🛡️ AuthSphere Control Center</h1>
          <p style={{ color: '#94a3b8', margin: '4px 0 0 0' }}>IoT Device Security & ECC Cryptographic Identity Management</p>
        </div>
        <span style={{ background: '#10b981', color: '#022c22', padding: '6px 16px', borderRadius: '20px', fontWeight: 'bold', fontSize: '13px' }}>
          SYSTEM OPERATIONAL
        </span>
      </header>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '20px', marginBottom: '32px' }}>
        <div style={{ background: '#1e293b', padding: '20px', borderRadius: '12px', border: '1px solid #334155' }}>
          <div style={{ color: '#94a3b8', fontSize: '13px', textTransform: 'uppercase', fontWeight: 'bold' }}>Active Entities</div>
          <div style={{ color: '#38bdf8', fontSize: '32px', fontWeight: 'bold', marginTop: '8px' }}>{stats.active_entities}</div>
        </div>
        <div style={{ background: '#1e293b', padding: '20px', borderRadius: '12px', border: '1px solid #334155' }}>
          <div style={{ color: '#94a3b8', fontSize: '13px', textTransform: 'uppercase', fontWeight: 'bold' }}>Pending Enrollment</div>
          <div style={{ color: '#f59e0b', fontSize: '32px', fontWeight: 'bold', marginTop: '8px' }}>{stats.pending}</div>
        </div>
        <div style={{ background: '#1e293b', padding: '20px', borderRadius: '12px', border: '1px solid #334155' }}>
          <div style={{ color: '#94a3b8', fontSize: '13px', textTransform: 'uppercase', fontWeight: 'bold' }}>Revoked Identities</div>
          <div style={{ color: '#ef4444', fontSize: '32px', fontWeight: 'bold', marginTop: '8px' }}>{stats.revoked}</div>
        </div>
        <div style={{ background: '#1e293b', padding: '20px', borderRadius: '12px', border: '1px solid #334155' }}>
          <div style={{ color: '#94a3b8', fontSize: '13px', textTransform: 'uppercase', fontWeight: 'bold' }}>Rotations (24h)</div>
          <div style={{ color: '#10b981', fontSize: '32px', fontWeight: 'bold', marginTop: '8px' }}>{stats.rotations_24h}</div>
        </div>
      </div>

      <div style={{ background: '#1e293b', padding: '24px', borderRadius: '12px', border: '1px solid #334155' }}>
        <h2 style={{ color: '#f8fafc', fontSize: '18px', marginTop: 0 }}>Registered Fleet Identities</h2>
        <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '16px', fontSize: '14px' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #334155', color: '#94a3b8', textAlign: 'left' }}>
              <th style={{ padding: '12px 8px' }}>Entity ID</th>
              <th style={{ padding: '12px 8px' }}>Type</th>
              <th style={{ padding: '12px 8px' }}>Role</th>
              <th style={{ padding: '12px 8px' }}>State</th>
              <th style={{ padding: '12px 8px' }}>Cert Serial</th>
            </tr>
          </thead>
          <tbody>
            <tr style={{ borderBottom: '1px solid #0f172a' }}>
              <td style={{ padding: '12px 8px', fontWeight: 'bold', color: '#38bdf8' }}>dev-esp32-01</td>
              <td style={{ padding: '12px 8px' }}>device</td>
              <td style={{ padding: '12px 8px' }}>sensor</td>
              <td style={{ padding: '12px 8px' }}><span style={{ color: '#10b981', fontWeight: 'bold' }}>● ACTIVE</span></td>
              <td style={{ padding: '12px 8px', fontFamily: 'monospace' }}>3fa92c815e90d1</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}
