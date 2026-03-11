import React, { useEffect, useState } from "react";
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, Legend } from "recharts";

const COLORS = ["#0088FE", "#00C49F", "#FFBB28", "#FF8042"];

function SecurityDashboard() {
  const [data, setData] = useState(null);

  useEffect(() => {
    fetch("/api/security-score")
      .then((res) => res.json())
      .then(setData);
  }, []);

  if (!data) return <div>Loading...</div>;

  const pieData = [
    { name: "Weak", value: data.weak_passwords },
    { name: "Reused", value: data.reused_passwords },
    { name: "Breached", value: data.breached_passwords },
    { name: "Strong", value: data.total_passwords - data.weak_passwords - data.reused_passwords - data.breached_passwords }
  ];

  return (
    <div>
      <h2>Passwords Overview</h2>
      <PieChart width={300} height={200}>
        <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={60} fill="#8884d8" label>
          {pieData.map((entry, index) => (
            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
          ))}
        </Pie>
        <Tooltip />
        <Legend />
      </PieChart>
      <h2>Security Score: {data.security_score}</h2>
      <h3>Recent Logins</h3>
      <BarChart width={400} height={200} data={data.recent_logins}>
        <XAxis dataKey="time" />
        <YAxis />
        <Tooltip />
        <Bar dataKey="user_id" fill="#8884d8" />
      </BarChart>
    </div>
  );
}

export default SecurityDashboard;
