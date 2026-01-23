import { useState, useEffect } from 'react';
import axios from 'axios';
import { AlertTriangle, CheckCircle, Shield, User, Globe, Clock, RefreshCw } from 'lucide-react';

const API_BASE = '/api';

function App() {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchIncidents = async () => {
    setLoading(true);
    try {
      const response = await axios.get(`${API_BASE}/incidents`);
      setIncidents(response.data.sort((a, b) => new Date(b.created_at) - new Date(a.created_at)));
    } catch (error) {
      console.error('Error fetching incidents:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
    const interval = setInterval(fetchIncidents, 5000);
    return () => clearInterval(interval);
  }, []);

  const resolveIncident = async (id) => {
    try {
      await axios.post(`${API_BASE}/incidents/${id}/resolve`);
      fetchIncidents();
    } catch (error) {
      console.error('Error resolving incident:', error);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'text-red-500 bg-red-100 border-red-200';
      case 'high': return 'text-orange-500 bg-orange-100 border-orange-200';
      case 'medium': return 'text-yellow-600 bg-yellow-100 border-yellow-200';
      default: return 'text-blue-500 bg-blue-100 border-blue-200';
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'new': return 'bg-purple-100 text-purple-700';
      case 'in_progress': return 'bg-blue-100 text-blue-700';
      case 'resolved': return 'bg-green-100 text-green-700';
      default: return 'bg-gray-100 text-gray-700';
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100 w-full p-8">
      <header className="mb-8 flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <Shield className="text-blue-500 w-8 h-8" />
            SOAR-lite Dashboard
          </h1>
          <p className="text-gray-400 mt-1">Automated Incident Response Orchestrator</p>
        </div>
        <button 
          onClick={fetchIncidents}
          className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 px-4 py-2 rounded-lg transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </header>

      <main>
        <div className="grid gap-6">
          {incidents.length === 0 && !loading ? (
            <div className="bg-gray-800 p-12 rounded-xl text-center border border-gray-700">
              <CheckCircle className="w-12 h-12 text-green-500 mx-auto mb-4" />
              <p className="text-xl font-medium">No incidents detected. All quiet on the front.</p>
            </div>
          ) : (
            incidents.map((incident) => (
              <div key={incident.id} className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden shadow-lg transition-all hover:border-gray-600">
                <div className="p-6">
                  <div className="flex justify-between items-start mb-4">
                    <div className="flex items-center gap-3">
                      <div className={`p-2 rounded-lg border ${getSeverityColor(incident.alert.severity)}`}>
                        <AlertTriangle className="w-6 h-6" />
                      </div>
                      <div>
                        <h3 className="text-lg font-semibold">{incident.alert.event_type}</h3>
                        <p className="text-sm text-gray-400">{incident.alert.source}</p>
                      </div>
                    </div>
                    <div className="flex flex-col items-end gap-2">
                      <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider ${getStatusBadge(incident.status)}`}>
                        {incident.status.replace('_', ' ')}
                      </span>
                      <span className="text-xs text-gray-500 flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {new Date(incident.created_at).toLocaleString()}
                      </span>
                    </div>
                  </div>

                  <p className="text-gray-300 mb-6">{incident.alert.description}</p>

                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
                    {incident.alert.source_ip && (
                      <div className="flex items-center gap-2 text-sm text-gray-400 bg-gray-900/50 p-2 rounded">
                        <Globe className="w-4 h-4" />
                        <span>Source IP: <span className="text-gray-200">{incident.alert.source_ip}</span></span>
                      </div>
                    )}
                    {incident.alert.user_id && (
                      <div className="flex items-center gap-2 text-sm text-gray-400 bg-gray-900/50 p-2 rounded">
                        <User className="w-4 h-4" />
                        <span>User: <span className="text-gray-200">{incident.alert.user_id}</span></span>
                      </div>
                    )}
                  </div>

                  {incident.automated_action_taken && (
                    <div className="mb-6 p-4 bg-blue-900/20 border border-blue-900/30 rounded-lg">
                      <h4 className="text-sm font-semibold text-blue-400 mb-1 flex items-center gap-2">
                        <Shield className="w-4 h-4" />
                        Automated Action Taken
                      </h4>
                      <p className="text-sm text-blue-200">{incident.automated_action_taken}</p>
                    </div>
                  )}

                  <div className="flex justify-end gap-3 pt-4 border-t border-gray-700">
                    {incident.status !== 'resolved' && (
                      <button 
                        onClick={() => resolveIncident(incident.id)}
                        className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded font-medium transition-colors"
                      >
                        Resolve Incident
                      </button>
                    )}
                    <button className="bg-gray-700 hover:bg-gray-600 px-4 py-2 rounded font-medium transition-colors">
                      View Details
                    </button>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </main>
    </div>
  );
}

export default App;
