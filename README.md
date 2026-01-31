# sshcmgr
Expire, Revoke and cycle SSH Keys

⏺ Phase 4 CLI implementation is now complete. Here's what was created:                                                            
                                                                                                                                  
  Environment commands (src/sshmgr/cli/commands/environment.py):                                                                  
  - sshmgr env init <name> - Initialize environment with CA keypairs                                                              
  - sshmgr env list - List all environments                                                                                       
  - sshmgr env show <name> - Show environment details                                                                             
  - sshmgr env delete <name> - Delete an environment                                                                              
  - sshmgr env get-ca <name> --type user|host - Get CA public key                                                                 
                                                                                                                                  
  Certificate commands (src/sshmgr/cli/commands/cert.py):                                                                         
  - sshmgr cert sign-user - Sign user certificate                                                                                 
  - sshmgr cert sign-host - Sign host certificate                                                                                 
  - sshmgr cert list - List issued certificates                                                                                   
  - sshmgr cert show - Show certificate details                                                                                   
  - sshmgr cert revoke - Revoke a certificate                                                                                     
                                                                                                                                  
  CA rotation commands (src/sshmgr/cli/commands/rotate.py):                                                                       
  - sshmgr rotate ca - Rotate a CA with grace period                                                                              
  - sshmgr rotate status - Show rotation status                                                                                   
  - sshmgr rotate cleanup - Clean up expired old CAs                                                                              
                                                                                                                                  
  All commands support:                                                                                                           
  - JSON output (-f json)                                                                                                         
  - Confirmation prompts with --force override                                                                                    
  - Spinners for long operations                                                                                                  
  - Rich console output with colors 

API Schemas (src/sshmgr/api/schemas.py):                                                                                        
  - Request/response models for environments, certificates, CA rotation                                                           
  - Validation for SSH public keys, validity periods                                                                              
  - Error response schemas                                                                                                        
                                                                                                                                  
  Dependencies (src/sshmgr/api/dependencies.py):                                                                                  
  - Database session management                                                                                                   
  - Key storage access                                                                                                            
  - Repository factories                                                                                                          
  - Authorization helpers (require_env_viewer, require_env_operator, require_env_admin)                                           
                                                                                                                                  
  Main App (src/sshmgr/api/main.py):                                                                                              
  - FastAPI app with lifespan management                                                                                          
  - CORS middleware                                                                                                               
  - Validation error handling                                                                                                     
  - Route registration                                                                                                            
                                                                                                                                  
  Routes:                                                                                                                         
  - health.py - /api/v1/health, /api/v1/ready, /api/v1/version                                                                    
  - environments.py - Full CRUD + CA rotation endpoints                                                                           
  - certificates.py - Sign user/host certs, list, revoke, search by key ID                                                        
                                                                                                                                  
  API Features:                                                                                                                   
  - JWT authentication via Keycloak                                                                                               
  - Role-based access control (admin/operator/viewer)                                                                             
  - Environment-level access control                                                                                              
  - Automatic OpenAPI documentation at /api/docs                                                                                  
  - Pagination support for certificate listing   

   Documentation Files:                                                                                                            
  ┌──────────────────┬────────────────────────────────────────────────┐                                                           
  │       File       │                  Description                   │                                                           
  ├──────────────────┼────────────────────────────────────────────────┤                                                           
  │ README.md        │ Documentation index and overview               │                                                           
  ├──────────────────┼────────────────────────────────────────────────┤                                                           
  │ architecture.md  │ System design, components, data flow diagrams  │                                                           
  ├──────────────────┼────────────────────────────────────────────────┤                                                           
  │ installation.md  │ Development and production setup guide         │                                                           
  ├──────────────────┼────────────────────────────────────────────────┤                                                           
  │ configuration.md │ Environment variables and settings reference   │                                                           
  ├──────────────────┼────────────────────────────────────────────────┤                                                           
  │ cli-reference.md │ Complete CLI command documentation             │                                                           
  ├──────────────────┼────────────────────────────────────────────────┤                                                           
  │ api-reference.md │ REST API endpoints with examples               │                                                           
  ├──────────────────┼────────────────────────────────────────────────┤                                                           
  │ testing.md       │ Test suite guide, fixtures, and best practices │                                                           
  ├──────────────────┼────────────────────────────────────────────────┤                                                           
  │ security.md      │ Security model, threat analysis, and checklist │                                                           
  └──────────────────┴────────────────────────────────────────────────┘                                                           
  Mermaid Diagrams (docs/images/):                                                                                                
  ┌───────────────────────┬─────────────────────────────────────┐                                                                 
  │         File          │             Description             │                                                                 
  ├───────────────────────┼─────────────────────────────────────┤                                                                 
  │ architecture.mmd      │ System architecture flowchart       │                                                                 
  ├───────────────────────┼─────────────────────────────────────┤                                                                 
  │ auth-flow.mmd         │ Device flow authentication sequence │                                                                 
  ├───────────────────────┼─────────────────────────────────────┤                                                                 
  │ cert-signing-flow.mmd │ Certificate signing sequence        │                                                                 
  ├───────────────────────┼─────────────────────────────────────┤                                                                 
  │ data-model.mmd        │ Entity-relationship diagram         │                                                                 
  └───────────────────────┴─────────────────────────────────────┘                                                                 
  The Mermaid diagrams can be rendered to images using:                                                                           
  - GitHub (renders .mmd files automatically)                                                                                     
  - VS Code with Mermaid extension                                                                                                
  - mmdc CLI tool: npx @mermaid-js/mermaid-cli -i file.mmd -o file.png 

  Structured Logging (src/sshmgr/logging.py):                                                                                     
  - JSON and text formatters                                                                                                      
  - Structured logger with context support                                                                                        
  - Audit logger for security-relevant events (certificate signing, revocation, CA rotation)                                      
  - Configurable log levels via SSHMGR_LOG_LEVEL and SSHMGR_LOG_FORMAT                                                            
                                                                                                                                  
  Prometheus Metrics (src/sshmgr/metrics.py):                                                                                     
  - Certificate metrics: issued, revoked, active counts                                                                           
  - HTTP request metrics: count, duration histogram                                                                               
  - CA rotation tracking                                                                                                          
  - Authentication metrics                                                                                                        
  - Endpoint at /api/v1/metrics                                                                                                   
                                                                                                                                  
  Docker Support:                                                                                                                 
  - Dockerfile - Multi-stage build with security best practices (non-root user, minimal image)                                    
  - docker-compose.yml - Development and production profiles                                                                      
  - .dockerignore - Optimized build context                                                                                       
  - .env.example - Template for environment configuration                                                                         
                                                                                                                                  
  Production Commands (Makefile):                                                                                                 
  make docker-build     # Build the image                                                                                         
  make docker-prod      # Start production stack                                                                                  
  make docker-prod-down # Stop production stack                                                                                   
  make docker-prod-logs # View logs                                                                                               
                                                                                                                                  
  Updated Dependencies (pyproject.toml):                                                                                          
  - Added prometheus-client>=0.19.0                                                                                               
                                                                                                                                  
  The sshmgr application is now production-ready with:                                                                            
  - Structured JSON logging for log aggregation                                                                                   
  - Prometheus metrics for monitoring                                                                                             
  - Docker deployment                                                                                                             
  - Health checks for orchestration                                                                                               
  - Graceful startup/shutdown  
  

  New Unit Test Files Created:                                                                                                    
  File: tests/unit/test_logging.py                                                                                                
  Tests: 32 tests                                                                                                                 
  Coverage: AuditAction, JSONFormatter, TextFormatter, StructuredLogger, AuditLogger, setup_logging, get_logger                   
  ────────────────────────────────────────                                                                                        
  File: tests/unit/test_metrics.py                                                                                                
  Tests: 28 tests                                                                                                                 
  Coverage: All Prometheus metrics, recording functions, context managers, middleware                                             
  ────────────────────────────────────────                                                                                        
  File: tests/unit/test_cli_output.py                                                                                             
  Tests: 35 tests                                                                                                                 
  Coverage: OutputFormat, print functions, formatters, create_table, confirm                                                      
  ────────────────────────────────────────                                                                                        
  File: tests/unit/test_cli_main.py                                                                                               
  Tests: 23 tests                                                                                                                 
  Coverage: Context, async_command, handle_errors, CLI groups and shortcuts                                                       
  ────────────────────────────────────────                                                                                        
  File: tests/unit/test_api.py                                                                                                    
  Tests: 22 tests                                                                                                                 
  Coverage: Health endpoints, app creation, dependencies, parse_validity, RequireEnvAccess                                        
  ────────────────────────────────────────                                                                                        
  File: tests/unit/test_api_schemas.py                                                                                            
  Tests: 45 tests                                                                                                                 
  Coverage: All Pydantic schemas including validation rules                                                                       
  Full Test Suite:                                                                                                                
                                                                                                                                  
  tests/                                                                                                                          
  ├── conftest.py              # Shared fixtures                                                                                  
  ├── unit/                                                                                                                       
  │   ├── test_api_schemas.py  # NEW - API schema validation                                                                      
  │   ├── test_api.py          # NEW - API endpoints and dependencies                                                             
  │   ├── test_auth.py         # Authentication module (existing)                                                                 
  │   ├── test_ca.py           # Certificate Authority (existing)                                                                 
  │   ├── test_cli_main.py     # NEW - CLI commands                                                                               
  │   ├── test_cli_output.py   # NEW - CLI output formatting                                                                      
  │   ├── test_encrypted_keys.py # Key encryption (existing)                                                                      
  │   ├── test_logging.py      # NEW - Structured logging and audit                                                               
  │   ├── test_metrics.py      # NEW - Prometheus metrics                                                                         
  │   └── test_storage.py      # Database models (existing)                                                                       
  └── integration/                                                                                                                
      └── test_repositories.py # Database repositories (existing)                                                                 
                                                                                                                                  
  To run the tests:                                                                                                               
  make install-dev  # Install dependencies                                                                                        
  make test         # Run unit tests                                                                                              
  make test-cov     # Run with coverage report                                                                                    
                                                   
  New Integration Tests Created:                                                                                                  
  ┌──────────────────────────┬───────┬────────────────────────────────────────────────────────────────────┐                       
  │           File           │ Lines │                              Coverage                              │                       
  ├──────────────────────────┼───────┼────────────────────────────────────────────────────────────────────┤                       
  │ test_api_integration.py  │ 661   │ Full API endpoint testing with mocked auth and in-memory DB        │                       
  ├──────────────────────────┼───────┼────────────────────────────────────────────────────────────────────┤                       
  │ test_auth_integration.py │ 576   │ Keycloak config, JWT claims, RBAC, credential storage, device flow │                       
  ├──────────────────────────┼───────┼────────────────────────────────────────────────────────────────────┤                       
  │ test_ca_integration.py   │ 586   │ CA generation, user/host cert signing, full certificate workflows  │                       
  ├──────────────────────────┼───────┼────────────────────────────────────────────────────────────────────┤                       
  │ test_cli_integration.py  │ 376   │ CLI commands, help text, shortcuts, output formats                 │                       
  └──────────────────────────┴───────┴────────────────────────────────────────────────────────────────────┘                       
  Complete Test Suite:                                                                                                            
                                                                                                                                  
  tests/                                                                                                                          
  ├── conftest.py                      # Shared fixtures                                                                          
  ├── unit/                            # 10 test files, 3,889 lines                                                               
  │   ├── test_api.py                  # API dependencies and health endpoints                                                    
  │   ├── test_api_schemas.py          # Pydantic schema validation                                                               
  │   ├── test_auth.py                 # Auth module unit tests                                                                   
  │   ├── test_ca.py                   # CA unit tests                                                                            
  │   ├── test_cli_main.py             # CLI context and decorators                                                               
  │   ├── test_cli_output.py           # Output formatting                                                                        
  │   ├── test_encrypted_keys.py       # Encryption tests                                                                         
  │   ├── test_logging.py              # Logging and audit                                                                        
  │   ├── test_metrics.py              # Prometheus metrics                                                                       
  │   └── test_storage.py              # Database models                                                                          
  └── integration/                     # 5 test files, 2,625 lines                                                                
      ├── test_api_integration.py      # End-to-end API tests                                                                     
      ├── test_auth_integration.py     # Auth flow tests                                                                          
      ├── test_ca_integration.py       # Certificate workflows                                                                    
      ├── test_cli_integration.py      # CLI command tests                                                                        
      └── test_repositories.py         # Repository CRUD tests                                                                    
                                                                                                                                  
  Total: 6,516 lines of test code                                                                                                 
                                                                                                                                  
  Key Test Scenarios Covered:                                                                                                     
                                                                                                                                  
  - API: Environment CRUD, certificate signing/revocation, CA rotation, authorization                                             
  - CLI: All command groups, shortcuts, output formats, error handling                                                            
  - CA: Key generation (Ed25519/RSA/ECDSA), certificate signing, verification with ssh-keygen                                     
  - Auth: Token handling, RBAC, environment isolation, credential storage                                                         
                                                                                                                                  
  Running the tests:                                                                                                              
  make test           # Unit tests only                                                                                           
  make test-integ     # Integration tests only                                                                                    
  make test-all       # All tests                                                                                                 
  make test-cov       # With coverage report    

PYTHONPATH=src .venv/bin/pytest tests/ -v --tb=short 2>&1 | tail -30