import { useMemo, useState } from "react";

function App() {
  const [alertFilter, setAlertFilter] = useState("ALL");
  const [search, setSearch] = useState("");

  const events = [
    {
      src_ip: "192.168.1.10",
      dst_ip: "10.0.0.5",
      protocol: "TCP",
      src_port: 54321,
      dst_port: 443,
      packet_len: 512,
    },
    {
      src_ip: "192.168.1.11",
      dst_ip: "10.0.0.5",
      protocol: "UDP",
      src_port: 53000,
      dst_port: 53,
      packet_len: 128,
    },
    {
      src_ip: "192.168.1.12",
      dst_ip: "10.0.0.8",
      protocol: "TCP",
      src_port: 49152,
      dst_port: 8000,
      packet_len: 1024,
    },
  ];

  const inventory = [
    {
      endpoint: "/api/v1/products/{id}",
      method: "GET",
      status: "DOCUMENTED",
    },
    {
      endpoint: "/api/v1/orders/{id}",
      method: "GET",
      status: "DOCUMENTED",
    },
    {
      endpoint: "/api/v1/internal/debug",
      method: "GET",
      status: "SHADOW API",
    },
    {
      endpoint: "/api/v1/users/{id}",
      method: "GET",
      status: "DOCUMENTED",
    },
  ];

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

  const filteredAlerts = useMemo(() => {
    return alerts.filter((alert) => {
      const matchesFilter =
        alertFilter === "ALL" || alert.type === alertFilter;

      const matchesSearch =
        alert.type.toLowerCase().includes(search.toLowerCase()) ||
        alert.endpoint.toLowerCase().includes(search.toLowerCase());

      return matchesFilter && matchesSearch;
    });
  }, [alertFilter, search]);

  const shadowCount = inventory.filter(
    (item) => item.status === "SHADOW API"
  ).length;

  const bolaCount = alerts.filter((alert) => alert.type === "BOLA").length;

  const bflaCount = alerts.filter((alert) => alert.type === "BFLA").length;

  return (
    <div style={styles.app}>
      {/* HEADER */}
      <header style={styles.header}>
        <div>
          <h1 style={styles.title}>API-SENTINEL</h1>
          <p style={styles.subtitle}>
            API Security Monitoring Dashboard
          </p>
        </div>

        <div style={styles.live}>
          <span style={styles.dot}></span>
          SYSTEM ONLINE
        </div>
      </header>

      <main style={styles.main}>

        {/* STATISTICS */}
        <section style={styles.cards}>
          <StatCard
            title="Total APIs"
            value={inventory.length}
          />

          <StatCard
            title="Shadow APIs"
            value={shadowCount}
          />

          <StatCard
            title="BOLA Attacks"
            value={bolaCount}
          />

          <StatCard
            title="BFLA Attacks"
            value={bflaCount}
          />
        </section>

        {/* RECENT EVENTS */}
        <section style={styles.panel}>
          <h2 style={styles.heading}>Recent Events</h2>

          <div style={styles.tableWrapper}>
            <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>Source IP</th>
                  <th style={styles.th}>Destination IP</th>
                  <th style={styles.th}>Protocol</th>
                  <th style={styles.th}>Source Port</th>
                  <th style={styles.th}>Destination Port</th>
                  <th style={styles.th}>Packet Length</th>
                </tr>
              </thead>

              <tbody>
                {events.map((event, index) => (
                  <tr key={index}>
                    <td style={styles.td}>{event.src_ip}</td>
                    <td style={styles.td}>{event.dst_ip}</td>
                    <td style={styles.td}>
                      <span
                        style={
                          event.protocol === "TCP"
                            ? styles.tcp
                            : styles.udp
                        }
                      >
                        {event.protocol}
                      </span>
                    </td>
                    <td style={styles.td}>{event.src_port}</td>
                    <td style={styles.td}>{event.dst_port}</td>
                    <td style={styles.td}>{event.packet_len}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* API INVENTORY */}
        <section style={styles.panel}>
          <h2 style={styles.heading}>API Inventory</h2>

          <div style={styles.tableWrapper}>
            <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>Endpoint</th>
                  <th style={styles.th}>Method</th>
                  <th style={styles.th}>Status</th>
                </tr>
              </thead>

              <tbody>
                {inventory.map((item, index) => (
                  <tr key={index}>
                    <td style={styles.td}>{item.endpoint}</td>
                    <td style={styles.td}>{item.method}</td>

                    <td
                      style={
                        item.status === "DOCUMENTED"
                          ? styles.success
                          : styles.warning
                      }
                    >
                      {item.status}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* SECURITY ALERTS */}
        <section style={styles.panel}>
          <div style={styles.alertHeader}>
            <h2 style={styles.heading}>Security Alerts</h2>

            <div style={styles.controls}>
              <input
                type="text"
                placeholder="Search alerts..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                style={styles.search}
              />

              <select
                value={alertFilter}
                onChange={(e) => setAlertFilter(e.target.value)}
                style={styles.select}
              >
                <option value="ALL">All</option>
                <option value="BOLA">BOLA</option>
                <option value="BFLA">BFLA</option>
                <option value="Shadow API">Shadow API</option>
              </select>
            </div>
          </div>

          {filteredAlerts.length === 0 ? (
            <div style={styles.noAlerts}>
              No alerts found.
            </div>
          ) : (
            filteredAlerts.map((alert, index) => (
              <div key={index} style={styles.alert}>
                <div>
                  <strong style={styles.alertType}>
                    {alert.type}
                  </strong>

                  <p style={styles.endpoint}>
                    {alert.endpoint}
                  </p>
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

                <span
                  style={
                    alert.status === "BLOCKED"
                      ? styles.blocked
                      : styles.detected
                  }
                >
                  {alert.status}
                </span>
              </div>
            ))
          )}
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

  tableWrapper: {
    overflowX: "auto",
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
    whiteSpace: "nowrap",
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

  tcp: {
    color: "#60a5fa",
    fontWeight: "bold",
  },

  udp: {
    color: "#c084fc",
    fontWeight: "bold",
  },

  alertHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    gap: "20px",
    marginBottom: "10px",
  },

  controls: {
    display: "flex",
    gap: "10px",
  },

  search: {
    background: "#0f172a",
    color: "#e2e8f0",
    border: "1px solid #475569",
    borderRadius: "6px",
    padding: "9px 12px",
    outline: "none",
  },

  select: {
    background: "#0f172a",
    color: "#e2e8f0",
    border: "1px solid #475569",
    borderRadius: "6px",
    padding: "9px 12px",
    outline: "none",
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

  blocked: {
    color: "#f87171",
    fontSize: "13px",
    fontWeight: "bold",
  },

  detected: {
    color: "#fbbf24",
    fontSize: "13px",
    fontWeight: "bold",
  },

  noAlerts: {
    padding: "30px",
    textAlign: "center",
    color: "#94a3b8",
  },

  footer: {
    textAlign: "center",
    padding: "25px",
    color: "#64748b",
    borderTop: "1px solid #334155",
  },
};

export default App;