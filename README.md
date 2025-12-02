# Backend - Bot Analytics API

A Django REST Framework API for tracking and analyzing bot submissions, honeypot interactions, and attack attempts. This backend powers the bot analytics dashboard by providing comprehensive endpoints for data ingestion, analytics, and administration.

## Tech Stack

- **Django 5.2** - Web framework
- **Django REST Framework** - REST API toolkit
- **PostgreSQL** - Database with ArrayField support
- **Gunicorn** - Production WSGI server
- **uv** - Fast Python package manager
- **drf-yasg** - OpenAPI/Swagger documentation
- **django-filter** - Advanced filtering capabilities
- **django-cors-headers** - CORS handling

## Project Structure

```
backend/
├── codex_test/          # Django project settings
│   ├── settings.py      # Configuration
│   ├── urls.py          # URL routing
│   └── wsgi.py          # WSGI application
├── myapp/               # Main application
│   ├── models.py        # BotEvent, AttackType models
│   ├── views.py         # API views and ViewSets
│   ├── serializers.py   # DRF serializers
│   ├── routers.py       # URL router configuration
│   ├── filters.py       # Custom filter classes
│   ├── pagination.py    # Pagination settings
│   ├── utils.py         # Utility functions (attack detection, email extraction)
│   ├── patterns.py      # Attack pattern definitions
│   ├── enums.py         # Enum definitions
│   ├── management/      # Django management commands
│   │   └── commands/
│   │       ├── generate_fake_bot_data.py
│   │       └── reset_db.py
│   └── tests/           # Test suite
├── Dockerfile           # Multi-stage Docker build
├── docker-compose.yml   # Local development setup
├── entrypoint.sh        # Container entrypoint script
├── pyproject.toml       # Project dependencies (uv)
└── manage.py           # Django management script
```

## Models

### BotEvent
Tracks individual bot interactions with the system:
- **IP Address & Geo-location** - Source tracking
- **Request Metadata** - Method, path, headers, referer, origin
- **Email Extraction** - Automatically extracted from payloads
- **Attack Detection** - Boolean flag and category classification
- **Event Categories** - `scan`, `spam`, or `attack`
- **Data Details** - JSON field for flexible payload storage
- **Target Fields** - ArrayField for tracking which fields were targeted

### AttackType
Records detected attack attempts:
- **Attack Categories** - XSS, SQLI, LFI, CMD, TRAVERSAL, SSTI, OTHER
- **Pattern Matching** - Specific attack pattern detected
- **Target Field** - Which input field triggered the detection
- **Raw Values** - Original malicious payload

## API Endpoints

### Public Endpoints

#### `GET /api/snapshot/`
Returns summary analytics for the dashboard:
- Total events, injection attempts, unique IPs
- Top 3 attack categories
- Top 3 request paths

#### `GET /api/aggregate-paths/`
Path analytics with aggregation:
- Traffic counts per path
- Breakdown by event category (scan/spam/attack)
- Filtering, searching, and ordering support

#### `POST /api/contact-bot/`
Honeypot endpoint for bot submissions:
- Accepts form data (including hidden honeypot fields)
- Rate limiting by IP address
- Automatic attack detection
- Email extraction from payloads
- Can be disabled via `CONTACT_BOT_ENABLED` environment variable

### Authenticated Endpoints

All endpoints below require authentication (Basic Auth or Session Auth).

#### `GET /api/bot-events/`
List all bot events with:
- Pagination (25 per page)
- Filtering by IP, path, category, attack status, method
- Search across multiple fields
- Ordering by various fields

#### `GET /api/bot-events/{id}/`
Retrieve detailed bot event information

#### `GET /api/aggregate-ips/`
IP analytics with aggregation:
- Traffic and email counts per IP
- Attack and event category breakdowns
- Unified search across IP, referer, and email
- Filtering and ordering support

#### `GET /api/aggregate-ips/{id}/`
Detailed IP analytics with:
- All associated bot events
- Attack history
- Timeline information

#### `GET /api/attacks/`
List all detected attacks:
- Filtering by category, bot event, target field
- Search and ordering support

#### `GET /api/attacks/{id}/`
Retrieve detailed attack information

### API Documentation

- **Swagger UI**: `http://localhost:8000/api/docs/`
- Interactive API documentation with request/response examples

## Getting Started

### Prerequisites

- Python 3.13+
- PostgreSQL 16+
- uv (Python package manager)
- Docker & Docker Compose (optional, for containerized setup)

### Local Development Setup

1. **Install dependencies using uv:**

```bash
cd backend
uv sync
```

2. **Set up environment variables:**

Create `.envs/.local/.env`:

```env
DJANGO_SECRET_KEY=your-secret-key-here
DJANGO_DEBUG=True
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1
POSTGRES_DB=codex_test
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
DB_HOST=localhost
CORS_ALLOWED_ORIGINS=http://localhost:3000
CONTACT_BOT_ENABLED=True
CONTACT_BOT_RATE_LIMIT=10
```

3. **Set up the database:**

```bash
# Activate the virtual environment
source .venv/bin/activate

# Run migrations
python manage.py migrate

# Create a superuser (optional)
python manage.py createsuperuser
```

4. **Run the development server:**

```bash
python manage.py runserver
```

The API will be available at `http://localhost:8000`

### Docker Setup

1. **Set up environment files:**

Create `.envs/.local/.env` and `.envs/.env.db` with your configuration.

2. **Start services:**

```bash
docker-compose up --build
```

This will:
- Start PostgreSQL database
- Run migrations automatically
- Start Django with Gunicorn on port 8000

3. **Access the API:**

- API: `http://localhost:8000`
- API Docs: `http://localhost:8000/api/docs/`
- Admin: `http://localhost:8000/admin/`

## Environment Variables

### Required

- `DJANGO_SECRET_KEY` - Django secret key (generate a secure one for production)
- `POSTGRES_DB` - Database name
- `POSTGRES_USER` - Database user
- `POSTGRES_PASSWORD` - Database password
- `DB_HOST` - Database host (use `db` in Docker, `localhost` locally)

### Optional

- `DJANGO_DEBUG` - Enable debug mode (default: `False`)
- `DJANGO_ALLOWED_HOSTS` - Comma-separated list of allowed hosts
- `DJANGO_CSRF_TRUSTED_ORIGINS` - Comma-separated trusted origins for CSRF
- `CORS_ALLOWED_ORIGINS` - Comma-separated CORS origins (empty = allow all)
- `CONTACT_BOT_ENABLED` - Enable/disable honeypot endpoint (default: `True`)
- `CONTACT_BOT_RATE_LIMIT` - Rate limit per IP for honeypot endpoint (default: `10`)
- `DB_URL` - Full database URL (alternative to individual DB vars, supports Supabase/cloud DBs)
- `PORT` - Port to run on (default: `8000`)
- `RUN_MIGRATIONS` - Auto-run migrations on startup (default: `true`)

## Features

### Attack Detection

The system automatically detects various attack patterns:
- **XSS (Cross-Site Scripting)** - Script injection attempts
- **SQLI (SQL Injection)** - Database injection attempts
- **LFI (Local File Inclusion)** - File inclusion attacks
- **CMD (Command Injection)** - Command execution attempts
- **TRAVERSAL** - Directory traversal attempts
- **SSTI (Server-Side Template Injection)** - Template injection
- **OTHER** - Other suspicious patterns

Detection happens automatically when data is submitted to `/api/contact-bot/`.

### Event Categorization

Bot events are automatically categorized:
- **SCAN** - GET requests without data (reconnaissance)
- **SPAM** - POST requests with data but no attacks
- **ATTACK** - Requests containing detected attack patterns

### Email Extraction

The system automatically extracts email addresses from:
- Common email fields (`email`, `contact_email`, etc.)
- Message/body fields (searches for embedded emails)
- Uses regex pattern matching

### Rate Limiting

The honeypot endpoint (`/api/contact-bot/`) includes IP-based rate limiting to prevent abuse.

### Filtering & Search

All list endpoints support:
- **Django Filter** - Field-based filtering
- **Search** - Full-text search across relevant fields
- **Ordering** - Sort by any orderable field
- **Pagination** - Standard pagination (25 items per page)

## Management Commands

### Generate Fake Data

Create test data for development:

```bash
python manage.py generate_fake_bot_data --count 100
```

### Reset Database

Reset the database (drops all data):

```bash
python manage.py reset_db
```

Or use the shell script:

```bash
./reset_database.sh
```

## Testing

Run the test suite:

```bash
# Activate virtual environment
source .venv/bin/activate

# Run all tests
python manage.py test

# Or use pytest
pytest
```

Test files are located in `myapp/tests/`:
- `test_views.py` - View and endpoint tests
- `test_honeypot_view.py` - Honeypot endpoint tests
- `test_utils.py` - Utility function tests
- `conftest.py` - Pytest configuration
- `factories.py` - Factory Boy factories for test data

## Database

### PostgreSQL Features

The project uses PostgreSQL-specific features:
- **ArrayField** - For storing arrays of strings (target fields)
- **JSONField** - For flexible data storage
- **Composite Indexes** - Optimized for common query patterns

### Migrations

Create new migrations:

```bash
python manage.py makemigrations
```

Apply migrations:

```bash
python manage.py migrate
```

## Production Deployment

### Security Checklist

- [ ] Set `DJANGO_DEBUG=False`
- [ ] Generate a strong `DJANGO_SECRET_KEY`
- [ ] Configure `DJANGO_ALLOWED_HOSTS` with your domain
- [ ] Set `CORS_ALLOWED_ORIGINS` to your frontend domain
- [ ] Use HTTPS (configure `DJANGO_CSRF_TRUSTED_ORIGINS`)
- [ ] Use a production database (not SQLite)
- [ ] Set up proper authentication for admin endpoints
- [ ] Configure logging and monitoring
- [ ] Set up database backups

### Gunicorn Configuration

The Docker setup uses Gunicorn with 3 workers. For production, adjust based on your needs:

```bash
gunicorn codex_test.wsgi:application \
  --bind 0.0.0.0:8000 \
  --workers 4 \
  --threads 2 \
  --timeout 120
```

### Static Files

Collect static files for production:

```bash
python manage.py collectstatic --noinput
```

## API Authentication

### Basic Authentication

Most endpoints require authentication. Use Basic Auth:

```bash
curl -u username:password http://localhost:8000/api/bot-events/
```

### Session Authentication

For browser-based access, use Django's session authentication (login via `/admin/`).

## Performance Considerations

- **Database Indexes** - Composite indexes on common filter combinations
- **Query Optimization** - Uses `select_related` and `prefetch_related` where appropriate
- **Pagination** - All list endpoints are paginated
- **Caching** - Consider adding Redis for caching in production

## Troubleshooting

### Database Connection Issues

- Verify PostgreSQL is running
- Check `DB_HOST`, `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`
- For cloud databases (Supabase), use `DB_URL` with SSL mode

### Migration Errors

- Ensure PostgreSQL is running
- Check database permissions
- Try resetting: `python manage.py reset_db`

### CORS Issues

- Set `CORS_ALLOWED_ORIGINS` to your frontend URL
- Or set `CORS_ALLOW_ALL_ORIGINS=True` for development only

### Rate Limiting

If honeypot endpoint is rate limiting too aggressively:
- Adjust `CONTACT_BOT_RATE_LIMIT` environment variable
- Or disable rate limiting in the view code

## Related Documentation

- [Main README](../README.md) - Project overview
- [Frontend README](../frontend/README.md) - Frontend documentation
- [API Documentation](http://localhost:8000/api/docs/) - Interactive Swagger docs

## License

See main project README for license information.

