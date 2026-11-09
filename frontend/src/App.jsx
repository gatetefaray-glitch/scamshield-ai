
import React, { useState } from 'react';

// Supports local development and production backend URLs.
const API_BASE_URL = (
  import.meta.env.VITE_API_BASE_URL || ''
).replace(/\/+$/, '');

// Shared API request handler.
async function sendAnalysisRequest(endpoint, payload) {
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  const responseText = await response.text();
  let data;

  try {
    data = JSON.parse(responseText);
  } catch {
    throw new Error(
      responseText
        ? 'The server returned an invalid response.'
        : `The server returned an empty response (HTTP ${response.status}).`
    );
  }

  if (!response.ok) {
    throw new Error(data.error || `Request failed (HTTP ${response.status}).`);
  }

  return data;
}

// Risk colour helper.
function riskColor(risk) {
  if (risk === 'HIGH') return '#dc2626';
  if (risk === 'MEDIUM') return '#d97706';
  if (risk === 'LOW') return '#16a34a';
  return '#374151';
}

// Displays supplementary AI findings separately from rule-based risk.
function AIAnalysis({ result }) {
  if (!result) return null;

  const ai = result.ai_analysis;

  return (
    <div style={{
      marginTop: '1.2rem',
      padding: '1rem',
      background: '#eef2ff',
      border: '1px solid #c7d2fe',
      borderRadius: '10px'
    }}>
      <h3 style={{ marginTop: 0, color: '#3730a3' }}>
        AI Contextual Assessment
      </h3>

      <p>
        <strong>Analysis Mode: </strong>
        {result.analysis_mode === 'hybrid'
          ? 'Hybrid (Rule-based + AI)'
          : 'Rule-based fallback'}
      </p>

      {!ai ? (
        <p style={{ color: '#4b5563' }}>
          AI analysis is currently unavailable.
          The deterministic rule-based assessment is still available.
        </p>
      ) : (
        <>
          <p>
            <strong>AI Assessment: </strong>
            <span style={{
              color: ai.suspicious ? '#dc2626' : '#15803d',
              fontWeight: 'bold'
            }}>
              {ai.suspicious
                ? 'Suspicious indicators detected'
                : 'No suspicious indicators identified by AI'}
            </span>
          </p>

          <p>
            <strong>AI Confidence: </strong>
            {ai.confidence}%
          </p>

          <p style={{ fontSize: '0.85rem', color: '#4b5563' }}>
            This is the AI model's confidence score, not a probability
            that the message or URL is fraudulent.
          </p>

          {ai.indicators?.length > 0 && (
            <>
              <strong>Additional AI Observations:</strong>
              <ul>
                {ai.indicators.map((indicator, index) => (
                  <li key={index}>{indicator}</li>
                ))}
              </ul>
            </>
          )}

          {ai.explanation && (
            <div style={{ marginTop: '1rem' }}>
              <strong>AI Explanation:</strong>
              <p>{ai.explanation}</p>
            </div>
          )}

          {ai.recommendation && (
            <div style={{
              marginTop: '1rem',
              padding: '0.8rem',
              background: '#ffffff',
              borderRadius: '8px'
            }}>
              <strong>Recommended Action:</strong>
              <p>{ai.recommendation}</p>
            </div>
          )}
        </>
      )}

      <p style={{
        fontSize: '0.85rem',
        color: '#4b5563',
        marginBottom: 0
      }}>
        AI findings are supplementary. The deterministic risk score
        remains the authoritative screening result.
      </p>
    </div>
  );
}

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
      const data = await sendAnalysisRequest(
        '/api/analyze-url',
        { url }
      );

      setUrlResult(data);
    } catch (error) {
      setUrlResult({
        error: error.message || 'Failed to connect to backend server.',
      });
    } finally {
      setLoadingUrl(false);
    }
  };

  const handleAnalyzeMessage = async (e) => {
    e.preventDefault();
    setLoadingMessage(true);
    setMessageResult(null);

    try {
      const data = await sendAnalysisRequest(
        '/api/analyze-message',
        { message }
      );

      setMessageResult(data);
    } catch (error) {
      setMessageResult({
        error: error.message || 'Failed to connect to backend server.',
      });
    } finally {
      setLoadingMessage(false);
    }
  };

  return (
    <main style={{
      padding: '2rem',
      fontFamily: 'Arial, sans-serif',
      maxWidth: '850px',
      margin: '0 auto',
      color: '#1f2937'
    }}>
      <header style={{ marginBottom: '2rem' }}>
        <h1>ScamShield AI</h1>
        <p>
          Analyze links and text messages for potential security risks.
        </p>
      </header>

      {/* URL Analysis */}
      <section style={{
        marginBottom: '2rem',
        border: '1px solid #d1d5db',
        padding: '1.5rem',
        borderRadius: '12px'
      }}>
        <h2>Check URL Safety</h2>

        <form onSubmit={handleAnalyzeUrl}>
          <input
            type="text"
            placeholder="Enter URL (e.g. https://example.com)"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            required
            maxLength={2048}
            style={{
              width: '70%',
              padding: '0.7rem',
              marginRight: '0.5rem',
              marginBottom: '0.5rem',
              boxSizing: 'border-box'
            }}
          />

          <button type="submit" disabled={loadingUrl}>
            {loadingUrl ? 'Checking...' : 'Analyze URL'}
          </button>
        </form>

        {urlResult && (
          <div style={{
            marginTop: '1rem',
            background: '#f3f4f6',
            padding: '1rem',
            borderRadius: '8px'
          }}>
            {urlResult.error ? (
              <p style={{ color: '#dc2626' }}>{urlResult.error}</p>
            ) : (
              <>
                <h3>Deterministic Security Assessment</h3>

                <p>
                  <strong>Risk Level: </strong>
                  <strong style={{
                    color: riskColor(urlResult.risk)
                  }}>
                    {urlResult.risk}
                  </strong>
                </p>

                <p>
                  <strong>Risk Score: </strong>
                  {urlResult.risk_score}/100
                </p>

                {urlResult.warnings?.length > 0 ? (
                  <>
                    <strong>Flagged Indicators:</strong>
                    <ul>
                      {urlResult.warnings.map((warning, index) => (
                        <li key={index}>{warning}</li>
                      ))}
                    </ul>
                  </>
                ) : (
                  <p>No suspicious URL indicators were detected.</p>
                )}

                <p><em>{urlResult.notice}</em></p>

                <AIAnalysis result={urlResult} />
              </>
            )}
          </div>
        )}
      </section>

      {/* Message Analysis */}
      <section style={{
        border: '1px solid #d1d5db',
        padding: '1.5rem',
        borderRadius: '12px'
      }}>
        <h2>Check Message Content</h2>

        <form onSubmit={handleAnalyzeMessage}>
          <textarea
            rows="5"
            placeholder="Paste suspicious text or SMS here..."
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            required
            maxLength={10000}
            style={{
              width: '100%',
              padding: '0.7rem',
              marginBottom: '0.8rem',
              boxSizing: 'border-box'
            }}
          />

          <button type="submit" disabled={loadingMessage}>
            {loadingMessage ? 'Analyzing...' : 'Analyze Message'}
          </button>
        </form>

        {messageResult && (
          <div style={{
            marginTop: '1rem',
            background: '#f3f4f6',
            padding: '1rem',
            borderRadius: '8px'
          }}>
            {messageResult.error ? (
              <p style={{ color: '#dc2626' }}>
                {messageResult.error}
              </p>
            ) : (
              <>
                <h3>Deterministic Security Assessment</h3>

                <p>
                  <strong>Risk Level: </strong>
                  <strong style={{
                    color: riskColor(messageResult.risk)
                  }}>
                    {messageResult.risk}
                  </strong>
                </p>

                <p>
                  <strong>Risk Score: </strong>
                  {messageResult.risk_score}/100
                </p>

                {messageResult.indicators?.length > 0 ? (
                  <>
                    <strong>Flagged Indicators:</strong>
                    <ul>
                      {messageResult.indicators.map((indicator, index) => (
                        <li key={index}>{indicator}</li>
                      ))}
                    </ul>
                  </>
                ) : (
                  <p>No suspicious indicators were detected.</p>
                )}

                <p><em>{messageResult.notice}</em></p>

                <AIAnalysis result={messageResult} />
              </>
            )}
          </div>
        )}
      </section>

      <footer style={{
        marginTop: '2rem',
        fontSize: '0.85rem',
        color: '#6b7280'
      }}>
        <p>
          ScamShield AI provides preliminary automated screening only.
          A LOW result does not guarantee that a link or message is safe.
          Always verify suspicious requests independently.
        </p>
      </footer>
    </main>
  );
}

export default App;
