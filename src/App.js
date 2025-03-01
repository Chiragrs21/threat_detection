import React, { useState, useEffect } from 'react';
import { io } from 'socket.io-client';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { AlertCircle, Server, Activity } from 'lucide-react';
import './index.css';

// Connect to the Flask backend
const socket = io('http://localhost:5000', { reconnectionAttempts: 5 });

function Dashboard() {
  const [packets, setPackets] = useState([]);
  const [requestRates, setRequestRates] = useState([]);
  const [portStatus, setPortStatus] = useState({});
  const [alerts, setAlerts] = useState([]);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchData = async (url, setter) => {
      try {
        const res = await fetch(url);
        if (!res.ok) throw new Error(`Failed to fetch from ${url}: ${res.status}`);
        const data = await res.json();
        setter(data);
      } catch (err) {
        setError(prev => prev ? `${prev}; ${err.message}` : err.message);
      }
    };

    fetchData('http://localhost:5000/api/packets/recent', setPackets);
    fetchData('http://localhost:5000/api/stats/request_rate', setRequestRates);
    fetchData('http://localhost:5000/api/ports', setPortStatus);

    socket.on('connect', () => setError(null));
    socket.on('connect_error', () => setError('Failed to connect to server'));

    socket.on('new_packet', (packet) => {
      setPackets(prev => [...prev.slice(Math.max(0, prev.length - 99)), packet]);
    });

    socket.on('request_rate', (rate) => {
      setRequestRates(prev => [...prev.slice(Math.max(0, prev.length - 299)), rate]);
    });

    socket.on('port_status', (status) => setPortStatus(status));

    socket.on('port_change', (change) => {
      if (change.status === 'OPEN') {
        setAlerts(prev => [...prev, {
          id: Date.now(),
          type: 'port',
          message: `Port ${change.port} opened by ${change.program}`,
          timestamp: new Date().toISOString(),
          severity: 'warning'
        }]);
      }
    });

    socket.on('anomaly_alert', (anomaly) => {
      setAlerts(prev => [...prev, {
        id: Date.now(),
        type: 'traffic',
        message: `Traffic spike detected! ${anomaly.current_rate} req/s (${anomaly.increase_factor.toFixed(1)}x normal)`,
        timestamp: new Date().toISOString(),
        severity: 'high'
      }]);
      playAlertSound();
    });

    socket.on('http_attack', (attack) => {
      setAlerts(prev => [...prev, {
        id: Date.now(),
        type: 'http_attack',
        message: `${attack.attack_type.charAt(0).toUpperCase() + attack.attack_type.slice(1)} detected from ${attack.src_ip}: ${attack.payload}`,
        timestamp: new Date().toISOString(),
        severity: 'critical'
      }]);
      playAlertSound();
    });

    socket.on('spoofing_alert', (spoof) => {
      setAlerts(prev => [...prev, {
        id: Date.now(),
        type: 'spoofing',
        message: `Spoofed IP detected: ${spoof.src_ip} → ${spoof.dst_ip}`,
        timestamp: new Date().toISOString(),
        severity: 'high'
      }]);
      playAlertSound();
    });

    const playAlertSound = () => {
      try {
        const audio = new Audio('/alert.mp3');
        audio.play().catch(err => console.warn('Alert sound blocked:', err));
      } catch (err) {
        console.warn('Alert sound failed:', err);
      }
    };

    return () => {
      socket.off('connect');
      socket.off('connect_error');
      socket.off('new_packet');
      socket.off('request_rate');
      socket.off('port_status');
      socket.off('port_change');
      socket.off('anomaly_alert');
      socket.off('http_attack');
      socket.off('spoofing_alert');
    };
  }, []);

  const formatTimestamp = (timestamp) => {
    const date = typeof timestamp === 'string' ? new Date(timestamp) : new Date(timestamp * 1000);
    return date.toLocaleTimeString([], { hour12: true, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };

  return (
    <div className="flex flex-col min-h-screen bg-gray-100">
      {error && (
        <div className="bg-red-500 text-white p-2 text-center">
          Error: {error}
        </div>
      )}
      <header className="bg-gray-800 text-white p-4">
        <div className="container mx-auto">
          <h1 className="text-2xl font-bold">Threat Detection & Monitoring Platform</h1>
        </div>
      </header>

      <nav className="bg-gray-700 text-white">
        <div className="container mx-auto flex">
          {['dashboard', 'packets', 'ports', 'alerts'].map(tab => (
            <button
              key={tab}
              className={`px-4 py-2 ${activeTab === tab ? 'bg-blue-600' : ''}`}
              onClick={() => setActiveTab(tab)}
            >
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
              {tab === 'alerts' && alerts.length > 0 && (
                <span className="ml-2 bg-red-500 text-white rounded-full px-2 py-1 text-xs">
                  {alerts.length}
                </span>
              )}
            </button>
          ))}
        </div>
      </nav>

      <main className="flex-grow p-4">
        <div className="container mx-auto">
          {activeTab === 'dashboard' && (
            <div className="space-y-6">
              {/* Full-Width Traffic Monitor */}
              <div className="bg-white p-4 rounded shadow">
                <h2 className="text-xl font-semibold mb-4 flex items-center">
                  <Activity className="mr-2" /> Traffic Monitor
                </h2>
                <div className="h-64">
                  {requestRates.length > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={requestRates.map(r => ({
                        time: formatTimestamp(r.timestamp),
                        value: r.count
                      }))}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="time" />
                        <YAxis />
                        <Tooltip />
                        <Line type="monotone" dataKey="value" stroke="#3b82f6" strokeWidth="2" dot={false} />
                      </LineChart>
                    </ResponsiveContainer>
                  ) : (
                    <p className="text-gray-500">Loading traffic data...</p>
                  )}
                </div>
              </div>

              {/* Side-by-Side Open Ports and Recent Threats */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Open Ports */}
                <div className="bg-white p-4 rounded shadow">
                  <h2 className="text-xl font-semibold mb-4 flex items-center">
                    <Server className="mr-2" /> Open Ports
                  </h2>
                  <div className="flex flex-wrap gap-4">
                    {Object.entries(portStatus).length > 0 ? (
                      Object.entries(portStatus).map(([port, info]) => (
                        <div key={port} className="flex items-center space-x-2">
                          <div
                            className={`w-4 h-4 rounded-full ${info.status === 'OPEN' ? 'bg-green-500' : 'bg-gray-400'}`}
                            title={`${info.status} - ${info.program}`}
                          ></div>
                          <span className="text-sm font-medium">{port}</span>
                          <span className="text-sm text-gray-600">({info.program})</span>
                        </div>
                      ))
                    ) : (
                      <p className="text-gray-500">No open ports detected</p>
                    )}
                  </div>
                </div>

                {/* Recent Threats */}
                <div className="bg-white p-4 rounded shadow">
                  <h2 className="text-xl font-semibold mb-4 flex items-center">
                    <AlertCircle className="mr-2" /> Recent Threats
                  </h2>
                  <div className="overflow-y-auto max-h-64">
                    {alerts.length > 0 ? (
                      <ul className="divide-y">
                        {alerts.slice(-5).reverse().map(alert => (
                          <li key={alert.id} className="py-2">
                            <div className={`border-l-4 pl-3 ${alert.severity === 'critical' ? 'border-red-600' : alert.severity === 'high' ? 'border-red-500' : 'border-yellow-500'}`}>
                              <p className="font-medium">{alert.message}</p>
                              <p className="text-sm text-gray-600">{formatTimestamp(alert.timestamp)}</p>
                            </div>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-gray-500">No threats detected</p>
                    )}
                  </div>
                </div>
              </div>

              {/* Full-Width Network Activity */}
              <div className="bg-white p-4 rounded shadow">
                <h2 className="text-xl font-semibold mb-4">Network Activity (Live Packet Capture)</h2>
                <div className="bg-green-100 p-4 rounded">
                  {packets.length > 0 ? (
                    <ul className="divide-y">
                      {packets.slice(-10).reverse().map((packet, i) => (
                        <li key={i} className="py-2 flex justify-between items-center">
                          <div>
                            <span>{packet.src_ip}:{packet.src_port || 'N/A'}</span>
                            <span className="mx-2">→</span>
                            <span>{packet.dst_ip}:{packet.dst_port || 'N/A'}</span>
                          </div>
                          <div className="text-sm text-gray-600">
                            {formatTimestamp(packet.timestamp)} | Protocol: {packet.protocol} | Flags: {packet.flags || 'N/A'}
                          </div>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-gray-500">No recent packets</p>
                  )}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'packets' && (
            <div className="bg-white p-4 rounded shadow">
              <h2 className="text-xl font-semibold mb-4">Packet Monitor</h2>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Time</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Destination</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Protocol</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Flags</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {packets.slice().reverse().map((packet, i) => (
                      <tr key={i} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {formatTimestamp(packet.timestamp)}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm">
                          {packet.src_ip}:{packet.src_port || 'N/A'}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm">
                          {packet.dst_ip}:{packet.dst_port || 'N/A'}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm">{packet.protocol}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm">{packet.flags || 'N/A'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {activeTab === 'ports' && (
            <div className="bg-white p-4 rounded shadow">
              <h2 className="text-xl font-semibold mb-4">Port Scanner</h2>
              <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
                {Object.entries(portStatus).map(([port, info]) => (
                  <div key={port} className="border p-4 rounded shadow-sm bg-blue-50">
                    <h3 className="text-lg font-medium">Port {port}</h3>
                    <p className="text-sm text-gray-600">Status: {info.status}</p>
                    <p className="text-sm text-gray-600">Program: {info.program}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'alerts' && (
            <div className="bg-white p-4 rounded shadow">
              <h2 className="text-xl font-semibold mb-4">Alert Log</h2>
              <div className="overflow-y-auto max-h-96">
                {alerts.length > 0 ? (
                  <ul className="divide-y">
                    {alerts.slice().reverse().map(alert => (
                      <li key={alert.id} className="py-3">
                        <div className={`border-l-4 pl-3 ${alert.severity === 'critical' ? 'border-red-600' : alert.severity === 'high' ? 'border-red-500' : 'border-yellow-500'}`}>
                          <p className="font-medium">{alert.message}</p>
                          <p className="text-sm text-gray-600">
                            {formatTimestamp(alert.timestamp)} | Type: {alert.type.charAt(0).toUpperCase() + alert.type.slice(1)} | Severity: {alert.severity.charAt(0).toUpperCase() + alert.severity.slice(1)}
                          </p>
                        </div>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-gray-500">No alerts detected</p>
                )}
              </div>
            </div>
          )}
        </div>
      </main>

      <footer className="bg-gray-800 text-white p-4">
        <div className="container mx-auto text-center">
          <p>Threat Detection & Monitoring Platform</p>
        </div>
      </footer>
    </div>
  );
}

export default Dashboard;