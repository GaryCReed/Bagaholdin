# Development Guide

## Backend Development

### Prerequisites
- Go 1.20+
- PostgreSQL 12+

### Setup
```bash
cd backend
go mod download
```

### Running the server
```bash
go run main.go
```

The API will be available at `http://localhost:8080`

### API Endpoints

**Authentication:**
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login and get JWT token

**Protected Routes (require Authorization header):**
- `GET /api/health` - Health check
- `POST /api/exploits/run` - Run an exploit
- `GET /api/sessions` - Get all sessions
- `GET /api/ws` - WebSocket for real-time output

## Frontend Development

### Prerequisites
- Node.js 18+
- npm (or yarn)

### Setup
```bash
cd frontend
npm install
```

### Running development server
```bash
npm start
```

The frontend will be available at `http://localhost:3000`

### Building for production
```bash
npm run build
```

## Database

### Initialize PostgreSQL
```bash
psql -U postgres
CREATE DATABASE msf_web;
```

## Running Full Stack

### Terminal 1: Backend
```bash
cd backend
go run main.go
```

### Terminal 2: Frontend
```bash
cd frontend
npm start
```

### Terminal 3: PostgreSQL (if not running as service)
```bash
psql -U postgres -d msf_web
```

## Architecture Notes

- **Backend API**: RESTful design with WebSocket support for real-time streaming
- **Frontend State**: Zustand for state management
- **Database**: PostgreSQL with migrations run on startup
- **Authentication**: JWT tokens with Bearer scheme
- **Real-time Communication**: WebSocket for command output streaming

## Next Steps

- [ ] Implement actual msfconsole integration
- [ ] Add exploit runner logic
- [ ] Implement reconnaissance commands
- [ ] Add session persistence
- [ ] Add command history
- [ ] Implement user permissions
- [ ] Add logging and monitoring
