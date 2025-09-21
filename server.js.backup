const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

app.use(cors());
app.use(express.json());

// Basic routes
app.get('/', (req, res) => {
  res.json({ 
    message: 'LLM Legislative Tracker API', 
    status: 'OK',
    version: '4.0.0-LLM-POWERED',
    timestamp: new Date().toISOString()
  });
});

app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    version: '4.0.0-LLM-POWERED'
  });
});

app.get('/api', (req, res) => {
  res.json({ 
    message: 'Legislative Tracker API - LLM Powered Version', 
    status: 'OK',
    endpoints: ['GET /', 'GET /health', 'GET /api']
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`íº€ LLM Legislative Tracker running on port ${PORT}`);
  console.log(`í³¡ Health check: http://localhost:${PORT}/health`);
});

// Handle process termination
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  process.exit(0);
});
