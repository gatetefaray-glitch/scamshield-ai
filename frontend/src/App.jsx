import React, { useState } from 'react';

function App() {
  const [url, setUrl] = useState('');
  const [message, setMessage] = useState('');
  const [urlResult, setUrlResult] = useState(null);
  const [messageResult, setMessageResult] = useState(null);
  const [loadingUrl, setLoadingUrl] = useState(false);
  const [loadingMessage, setLoadingMessage] = useState(false);

  const handleAnalyzeUrl = async (e) => {
    e.preventDefault();
    setLoadingUrl(true);
    setUrlResult(null);

    try {
      const response = await fetch('http://localhost:5000/api/analyze-url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      const data = await response.json();
      setUrlResult(data);
    } catch (error) {
      setUrlResult({ error: 'Failed to connect to backend server.' });
    } finally {
      setLoadingUrl(false);
    }
  };

  const handleAnalyzeMessage = async (e) => {
    e.preventDefault();
    setLoadingMessage(true);
    setMessageResult(null);

    try {
      const response = await fetch('http://localhost:5000/api/analyze-message', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message }),
      });
      const data = await response.json();
      setMessageResult(data);
    } catch (error) {
      setMessageResult({ error: 'Failed to connect to backend server.' });
    } finally {
      setLoadingMessage(false);
    }
  };

  return (
    <div style={{ padding: '2rem', fontFamily: 'sans-serif', maxWidth: '800px', margin: '0 auto' }}>
      <h1>ScamShield AI 🛡️</h1>
      <p>Analyze links and text messages for security risks.</p>

      {/* URL Analysis Section */}
      <section style={{ marginBottom: '2rem', border: '1px solid #ccc', padding: '1rem', borderRadius: '8px' }}>
        <h2>Check URL Safety</h2>
        <form onSubmit={handleAnalyzeUrl}>
          <input
            type="text"
            placeholder="Enter URL (e.g. https://example.com)"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            style={{ width: '70%', padding: '0.5rem', marginRight: '0.5rem' }}
          />
          <button type="submit" disabled={loadingUrl} style={{ padding: '0.5rem 1rem' }}>
            {loadingUrl ? 'Checking...' : 'Analyze URL'}
          </button>
        </form>

        {urlResult && (
          <div style={{ marginTop: '1rem', background: '#f5f5f5', padding: '1rem', borderRadius: '4px' }}>
            {urlResult.error ? (
              <p style={{ color: 'red' }}>{urlResult.error}</p>
            ) : (
              <>
                <p><strong>Risk Level:</strong> {urlResult.risk}</p>
                {urlResult.warnings && urlResult.warnings.length > 0 && (
                  <div>
                    <strong>Warnings:</strong>
                    <ul>
                      {urlResult.warnings.map((w, index) => (
                        <li key={index}>{w}</li>
                      ))}
                    </ul>
                  </div>
                )}
                <p><em>{urlResult.notice}</em></p>
              </>
            )}
          </div>
        )}
      </section>

      {/* Message Analysis Section */}
      <section style={{ border: '1px solid #ccc', padding: '1rem', borderRadius: '8px' }}>
        <h2>Check Message Content</h2>
        <form onSubmit={handleAnalyzeMessage}>
          <textarea
            rows="4"
            placeholder="Paste suspicious text or SMS here..."
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            style={{ width: '100%', padding: '0.5rem', marginBottom: '0.5rem' }}
          />
          <button type="submit" disabled={loadingMessage} style={{ padding: '0.5rem 1rem' }}>
            {loadingMessage ? 'Analyzing...' : 'Analyze Message'}
          </button>
        </form>

        {messageResult && (
          <div style={{ marginTop: '1rem', background: '#f5f5f5', padding: '1rem', borderRadius: '4px' }}>
            {messageResult.error ? (
              <p style={{ color: 'red' }}>{messageResult.error}</p>
            ) : (
              <>
                <p><strong>Risk Level:</strong> {messageResult.risk}</p>
                {messageResult.indicators && messageResult.indicators.length > 0 && (
                  <div>
                    <strong>Flagged Keywords:</strong>
                    <ul>
                      {messageResult.indicators.map((word, index) => (
                        <li key={index}>{word}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </section>
    </div>
  );
}

export default App;
