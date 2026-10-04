-- BESTR3PS PostgreSQL Database Schema Initializer
-- Table for Administrator accounts and salt/hashed credentials
CREATE TABLE IF NOT EXISTS admin_users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(64) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Table for Active Administrator Sessions (Invalidated upon password change)
CREATE TABLE IF NOT EXISTS admin_sessions (
  token VARCHAR(128) PRIMARY KEY,
  username VARCHAR(64) NOT NULL REFERENCES admin_users(username) ON UPDATE CASCADE ON DELETE CASCADE,
  login_time BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Table for Customer Custom Product / Sourcing Requests
CREATE TABLE IF NOT EXISTS customer_requests (
  id VARCHAR(64) PRIMARY KEY,
  product_name VARCHAR(255) NOT NULL,
  description TEXT,
  reference_images JSONB DEFAULT '[]'::jsonb,
  contact_type VARCHAR(32) NOT NULL DEFAULT 'discord',
  contact_handle VARCHAR(128) NOT NULL,
  target_budget VARCHAR(64),
  status VARCHAR(32) NOT NULL DEFAULT 'pending',
  admin_notes TEXT,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Table for Site Analytics, Click Counts, and Aggregations
CREATE TABLE IF NOT EXISTS site_analytics (
  id VARCHAR(64) PRIMARY KEY,
  page_views BIGINT DEFAULT 0,
  daily_data JSONB DEFAULT '{}'::jsonb,
  products_data JSONB DEFAULT '{}'::jsonb,
  agents_data JSONB DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Indices for rapid lookup
CREATE INDEX IF NOT EXISTS idx_customer_requests_status ON customer_requests(status);
CREATE INDEX IF NOT EXISTS idx_customer_requests_created_at ON customer_requests(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires_at ON admin_sessions(expires_at);
