from fastapi import FastAPI

# Initialize the FastAPI microservice app
app = FastAPI(
    title="Secure Identity & RBAC Microservice",
    version="1.0.0",
    description="Enterprise Authentication, Role-Based Access Control, and Audit Logging Service"
)

@app.get("/api/v1/health", tags=["Health"])
def health_check():
    """Health check endpoint to verify microservice availability."""
    return {
        "status": "healthy",
        "service": "secure-identity-service",
        "version": "1.0.0"
    }