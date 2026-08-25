function App() {
  const alerts = [
    {
      type: "BOLA",
      endpoint: "/api/v1/orders/1002",
      severity: "CRITICAL",
      status: "BLOCKED",
    },
    {
      type: "BFLA",
      endpoint: "/api/v1/users/101",
      severity: "HIGH",
      status: "BLOCKED",
    },
    {
      type: "Shadow API",
      endpoint: "/api/v1/internal/debug",
      severity: "MEDIUM",
      status: "DETECTED",
    },
  ];

  return (
    <div style={styles.app}>
      <header style={styles.header}>
        <div>
          <h1 style={styles.title}>API-SENTINEL</h1>
          <p style={styles.subtitle}>API Security Monitoring Dashboard</p>
        </div>

        <div style={styles.live}>
          <span style={styles.dot}></span>
          SYSTEM ONLINE
        </div>
      </header>

      <main style={styles.main}>
        <section style={styles.cards}>
          <StatCard title="Total APIs" value="12" />
          <StatCard title="Shadow APIs" value="2" />
          <StatCard title="BOLA Attacks" value="3" />
          <StatCard title="BFLA Attacks" value="1" />
        </section>

        <section style={styles.panel}>
          <h2 style={styles.heading}>API Inventory</h2>

          <table style={styles.table}>
            <thead>
              <tr>
                <th style={styles.th}>Endpoint</th>
                <th style={styles.th}>Method</th>
                <th style={styles.th}>Status</th>
              </tr>
            </thead>

            <tbody>
              <tr>
                <td style={styles.td}>/api/v1/products/{`{id}`}</td>
                <td style={styles.td}>GET</td>
                <td style={styles.success}>DOCUMENTED</td>
              </tr>

              <tr>
                <td style={styles.td}>/api/v1/orders/{`{id}`}</td>
                <td style={styles.td}>GET</td>
                <td style={styles.success}>DOCUMENTED</td>
              </tr>

              <tr>
                <td style={styles.td}>/api/v1/internal/debug</td>
                <td style={styles.td}>GET</td>
                <td style={styles.warning}>SHADOW API</td>
              </tr>
            </tbody>
          </table>
        </section>

        <section style={styles.panel}>
          <h2 style={styles.heading}>Security Alerts</h2>

          {alerts.map((alert, index) => (
            <div key={index} style={styles.alert}>
              <div>
                <strong style={styles.alertType}>{alert.type}</strong>
                <p style={styles.endpoint}>{alert.endpoint}</p>
              </div>

              <span
                style={{
                  ...styles.badge,
                  ...(alert.severity === "CRITICAL"
                    ? styles.critical
                    : alert.severity === "HIGH"
                    ? styles.high
                    : styles.medium),
                }}
              >
                {alert.severity}
              </span>

              <span style={styles.status}>{alert.status}</span>
            </div>
          ))}
        </section>
      </main>

      <footer style={styles.footer}>
        API-Sentinel • Security Monitoring MVP
      </footer>
    </div>
  );
}

function StatCard({ title, value }) {
  return (
    <div style={styles.card}>
      <p style={styles.cardTitle}>{title}</p>
      <h2 style={styles.cardValue}>{value}</h2>
    </div>
  );
}

const styles = {
  app: {
    minHeight: "100vh",
    background: "#0f172a",
    color: "#e2e8f0",
    fontFamily: "Arial, sans-serif",
  },

  header: {
    padding: "25px 40px",
    background: "#111827",
    borderBottom: "1px solid #334155",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
  },

  title: {
    margin: 0,
    fontSize: "28px",
    letterSpacing: "2px",
  },

  subtitle: {
    margin: "6px 0 0",
    color: "#94a3b8",
  },

  live: {
    color: "#22c55e",
    fontWeight: "bold",
    display: "flex",
    alignItems: "center",
    gap: "8px",
  },

  dot: {
    width: "9px",
    height: "9px",
    background: "#22c55e",
    borderRadius: "50%",
    display: "inline-block",
  },

  main: {
    padding: "30px 40px",
    maxWidth: "1200px",
    margin: "auto",
  },

  cards: {
    display: "grid",
    gridTemplateColumns: "repeat(4, 1fr)",
    gap: "18px",
    marginBottom: "25px",
  },

  card: {
    background: "#1e293b",
    border: "1px solid #334155",
    borderRadius: "12px",
    padding: "22px",
  },

  cardTitle: {
    margin: 0,
    color: "#94a3b8",
    fontSize: "14px",
  },

  cardValue: {
    margin: "10px 0 0",
    fontSize: "32px",
  },

  panel: {
    background: "#1e293b",
    border: "1px solid #334155",
    borderRadius: "12px",
    padding: "22px",
    marginBottom: "25px",
  },

  heading: {
    marginTop: 0,
    fontSize: "20px",
  },

  table: {
    width: "100%",
    borderCollapse: "collapse",
  },

  th: {
    textAlign: "left",
    padding: "12px",
    color: "#94a3b8",
    borderBottom: "1px solid #475569",
  },

  td: {
    padding: "14px 12px",
    borderBottom: "1px solid #334155",
  },

  success: {
    color: "#22c55e",
    fontWeight: "bold",
  },

  warning: {
    color: "#f59e0b",
    fontWeight: "bold",
  },

  alert: {
    display: "grid",
    gridTemplateColumns: "1fr auto auto",
    gap: "20px",
    alignItems: "center",
    padding: "16px",
    borderBottom: "1px solid #334155",
  },

  alertType: {
    fontSize: "16px",
  },

  endpoint: {
    margin: "6px 0 0",
    color: "#94a3b8",
  },

  badge: {
    padding: "6px 10px",
    borderRadius: "6px",
    fontSize: "12px",
    fontWeight: "bold",
  },

  critical: {
    background: "#7f1d1d",
    color: "#fecaca",
  },

  high: {
    background: "#78350f",
    color: "#fed7aa",
  },

  medium: {
    background: "#713f12",
    color: "#fef08a",
  },

  status: {
    color: "#94a3b8",
    fontSize: "13px",
  },

  footer: {
    textAlign: "center",
    padding: "25px",
    color: "#64748b",
    borderTop: "1px solid #334155",
  },
};

export default App;