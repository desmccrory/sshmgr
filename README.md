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
  