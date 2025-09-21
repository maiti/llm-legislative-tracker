// Railway-compatible server.js configuration
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Sequelize, DataTypes } = require('sequelize');
const cron = require('node-cron');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Database configuration for Railway
let sequelize;

if (process.env.DATABASE_URL) {
  // Production: Use Railway's PostgreSQL
  sequelize = new Sequelize(process.env.DATABASE_URL, {
    dialect: 'postgres',
    protocol: 'postgres',
    logging: false,
    dialectOptions: {
      ssl: {
        require: true,
        rejectUnauthorized: false
      }
    }
  });
} else {
  // Development: Use SQLite (only if sqlite3 is installed)
  sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: process.env.NODE_ENV === 'production' ? ':memory:' : 'database.sqlite',
    logging: false
  });
}

// User Model
const User = sequelize.define('User', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: {
      isEmail: true
    }
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false
  },
  role: {
    type: DataTypes.ENUM('admin', 'user'),
    defaultValue: 'user'
  },
  status: {
    type: DataTypes.ENUM('pending', 'approved', 'rejected'),
    defaultValue: 'pending'
  },
  createdAt: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW
  },
  updatedAt: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW
  }
});

// Bill Model
const Bill = sequelize.define('Bill', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  bill_id: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  title: {
    type: DataTypes.TEXT,
    allowNull: false
  },
  description: {
    type: DataTypes.TEXT
  },
  state: {
    type: DataTypes.STRING(2),
    allowNull: false
  },
  session: {
    type: DataTypes.STRING,
    allowNull: false
  },
  status: {
    type: DataTypes.STRING,
    defaultValue: 'Introduced'
  },
  progress: {
    type: DataTypes.INTEGER,
    defaultValue: 1,
    validate: {
      min: 1,
      max: 5
    }
  },
  last_action: {
    type: DataTypes.TEXT
  },
  last_action_date: {
    type: DataTypes.DATE
  },
  sponsors: {
    type: DataTypes.JSON,
    defaultValue: []
  },
  subjects: {
    type: DataTypes.JSON,
    defaultValue: []
  },
  keywords: {
    type: DataTypes.JSON,
    defaultValue: []
  },
  url: {
    type: DataTypes.TEXT
  },
  pdf_url: {
    type: DataTypes.TEXT
  },
  full_text: {
    type: DataTypes.TEXT
  },
  source: {
    type: DataTypes.ENUM('legiscan', 'manual', 'llm'),
    defaultValue: 'llm'
  },
  ai_generated: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  },
  relevance_score: {
    type: DataTypes.FLOAT,
    defaultValue: 0.0
  },
  createdAt: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW
  },
  updatedAt: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW
  }
});

// Keyword Model
const TrackedKeyword = sequelize.define('TrackedKeyword', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  keyword: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  category: {
    type: DataTypes.STRING,
    defaultValue: 'general'
  },
  active: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  },
  weight: {
    type: DataTypes.FLOAT,
    defaultValue: 1.0
  }
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Admin middleware
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// LLM Bill Generation Function
async function generateLLMBills(keywords = []) {
  try {
    const keywordList = keywords.length > 0 ? keywords : [
      'healthcare', 'education', 'environment', 'technology', 'transportation',
      'housing', 'criminal justice', 'economic development', 'agriculture',
      'energy', 'immigration', 'veterans affairs', 'social services'
    ];

    const selectedKeywords = keywordList.sort(() => 0.5 - Math.random()).slice(0, 5);
    
    const prompt = `Generate 6 realistic legislative bills for US state legislatures. Each bill should be unique and address current policy issues related to these topics: ${selectedKeywords.join(', ')}.

For each bill, provide EXACTLY this JSON structure:
{
  "bills": [
    {
      "bill_id": "HB-2024-XXX",
      "title": "Specific descriptive title",
      "description": "Detailed 2-3 sentence description of what the bill does",
      "state": "XX",
      "session": "2024",
      "status": "Introduced",
      "progress": 1,
      "last_action": "Referred to Committee",
      "last_action_date": "2024-09-15",
      "sponsors": [{"name": "Rep. First Last", "party": "R", "district": "15"}],
      "subjects": ["topic1", "topic2"],
      "keywords": ["keyword1", "keyword2", "keyword3"],
      "url": "https://legislature.state.gov/bill/hb-2024-xxx"
    }
  ]
}

Requirements:
- Use realistic bill numbers (HB, SB, AB, etc.)
- Include various US states (CA, TX, NY, FL, etc.)
- Make bills address real policy challenges
- Include realistic sponsor names and details
- Ensure status is one of: Introduced, Committee, Floor, Passed, Signed, Vetoed
- Progress should be 1-5 (1=Introduced, 5=Signed)
- Use current dates in 2024
- Make each bill unique and substantive

RESPOND ONLY WITH VALID JSON. NO OTHER TEXT.`;

    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "claude-3-sonnet-20240229",
        max_tokens: 4000,
        messages: [{ role: "user", content: prompt }]
      })
    });

    if (!response.ok) {
      throw new Error(`API request failed: ${response.status}`);
    }

    const data = await response.json();
    let responseText = data.content[0].text;
    responseText = responseText.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
    
    const generatedData = JSON.parse(responseText);
    const bills = generatedData.bills || [];

    const savedBills = [];
    for (const billData of bills) {
      try {
        const existingBill = await Bill.findOne({ where: { bill_id: billData.bill_id } });
        if (existingBill) continue;

        const bill = await Bill.create({
          ...billData,
          source: 'llm',
          ai_generated: true,
          relevance_score: Math.random() * 0.5 + 0.5,
          last_action_date: new Date(billData.last_action_date)
        });
        savedBills.push(bill);
      } catch (error) {
        console.error('Error saving bill:', error);
      }
    }

    return savedBills;
  } catch (error) {
    console.error('Error generating LLM bills:', error);
    throw error;
  }
}

// Routes
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date(),
    database: sequelize.options.dialect,
    environment: process.env.NODE_ENV || 'development'
  });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Authentication routes
app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({
      email,
      password: hashedPassword,
      role: 'user',
      status: 'pending'
    });

    res.status(201).json({
      message: 'Registration successful. Awaiting admin approval.',
      user: { id: user.id, email: user.email, role: user.role, status: user.status }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (user.status !== 'approved') {
      return res.status(403).json({ error: `Account is ${user.status}. Contact admin for approval.` });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET || 'fallback-secret-key',
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: { id: user.id, email: user.email, role: user.role }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Bills routes
app.get('/api/bills', authenticateToken, async (req, res) => {
  try {
    const { search, state, status, source, page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;

    let whereClause = {};
    
    if (search) {
      whereClause[Sequelize.Op.or] = [
        { title: { [Sequelize.Op.iLike]: `%${search}%` } },
        { description: { [Sequelize.Op.iLike]: `%${search}%` } },
        { bill_id: { [Sequelize.Op.iLike]: `%${search}%` } }
      ];
    }
    
    if (state) whereClause.state = state;
    if (status) whereClause.status = status;
    if (source) whereClause.source = source;

    const bills = await Bill.findAndCountAll({
      where: whereClause,
      order: [['createdAt', 'DESC']],
      limit: parseInt(limit),
      offset: parseInt(offset)
    });

    res.json({
      bills: bills.rows,
      total: bills.count,
      page: parseInt(page),
      totalPages: Math.ceil(bills.count / limit)
    });
  } catch (error) {
    console.error('Error fetching bills:', error);
    res.status(500).json({ error: 'Failed to fetch bills' });
  }
});

app.post('/api/sync', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const keywords = req.body.keywords || [];
    const bills = await generateLLMBills(keywords);
    
    res.json({
      message: `Successfully generated ${bills.length} new bills`,
      bills: bills.map(bill => ({
        id: bill.id,
        bill_id: bill.bill_id,
        title: bill.title,
        state: bill.state,
        status: bill.status
      }))
    });
  } catch (error) {
    console.error('Sync error:', error);
    res.status(500).json({ error: 'Sync failed: ' + error.message });
  }
});

// Admin routes
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await User.findAll({
      attributes: ['id', 'email', 'role', 'status', 'createdAt'],
      order: [['createdAt', 'DESC']]
    });
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.patch('/api/admin/users/:id/status', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    
    if (!['pending', 'approved', 'rejected'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const user = await User.findByPk(id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.status = status;
    await user.save();

    res.json({ message: 'User status updated', user: { id: user.id, email: user.email, status: user.status } });
  } catch (error) {
    console.error('Error updating user status:', error);
    res.status(500).json({ error: 'Failed to update user status' });
  }
});

// Database initialization
async function initializeDatabase() {
  try {
    await sequelize.authenticate();
    console.log('Database connection established successfully.');
    
    await sequelize.sync({ alter: true });
    console.log('Database synchronized successfully.');

    // Create default admin user
    const adminExists = await User.findOne({ where: { email: 'admin@example.com' } });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await User.create({
        email: 'admin@example.com',
        password: hashedPassword,
        role: 'admin',
        status: 'approved'
      });
      console.log('Default admin user created: admin@example.com / admin123');
    }

    // Create default keywords
    const keywordExists = await TrackedKeyword.findOne();
    if (!keywordExists) {
      const defaultKeywords = [
        'healthcare', 'education', 'environment', 'technology', 'transportation',
        'housing', 'criminal justice', 'economic development', 'agriculture',
        'energy', 'immigration', 'veterans affairs', 'social services'
      ];
      
      for (const keyword of defaultKeywords) {
        await TrackedKeyword.create({ keyword, category: 'general' });
      }
      console.log('Default keywords created.');
    }

  } catch (error) {
    console.error('Unable to connect to the database:', error);
    process.exit(1);
  }
}

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Error handler
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
initializeDatabase().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 LLM Legislative Tracker running on port ${PORT}`);
    console.log(`📊 Database: ${sequelize.options.dialect}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  });
}).catch(error => {
  console.error('Failed to start server:', error);
  process.exit(1);
});

module.exports = app;