
import { useState } from "react";
import { ShieldCheck, Link, MessageSquare, Search } from "lucide-react";
import "./style.css";

function App() {
  const [url, setUrl] = useState("");
  const [message, setMessage] = useState("");
  const [result, setResult] = useState("");

  const scanURL = async () => {
    try {
      const response = await fetch("http://localhost:5000/api/analyze-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });

      const data = await response.json();
      setResult(JSON.stringify(data, null, 2));
    } catch {
      setResult("Backend is not connected. Start the Flask server.");
    }
  };

  const scanMessage = async () => {
    try {
      const response = await fetch("http://localhost:5000/api/analyze-message", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message })
      });

      const data = await response.json();
      setResult(JSON.stringify(data, null, 2));
    } catch {
      setResult("Backend is not connected. Start the Flask server.");
    }
  };

  return (
    <div className="app">
      <header>
        <h2><ShieldCheck /> ScamShield AI</h2>
        <span>Online Protection</span>
      </header>

      <main>
        <section className="hero">
          <h1>Stay Safe Online with ScamShield AI</h1>
          <p>Analyze suspicious links and messages before trusting them.</p>
        </section>

        <div className="scanner-grid">
          <section className="scanner">
            <Link size={30} />
            <h2>URL Scanner</h2>
            <p>Check suspicious website links.</p>
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter website URL..."
            />
            <button onClick={scanURL}>
              <Search size={18} /> Scan URL
            </button>
          </section>

          <section className="scanner">
            <MessageSquare size={30} />
            <h2>Message Scanner</h2>
            <p>Check suspicious messages.</p>
            <textarea
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Paste suspicious message..."
            />
            <button onClick={scanMessage}>
              <Search size={18} /> Scan Message
            </button>
          </section>
        </div>

        {result && (
          <section className="result">
            <h2>Analysis Results</h2>
            <pre>{result}</pre>
          </section>
        )}
      </main>
    </div>
  );
}

export default App;
