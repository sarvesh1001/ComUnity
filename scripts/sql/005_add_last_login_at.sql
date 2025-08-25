-- Add last_login_at column to users table
ALTER TABLE users ADD COLUMN last_login_at TIMESTAMP WITH TIME ZONE;

-- Create index for faster queries
CREATE INDEX idx_users_last_login ON users(last_login_at);