import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from src.app.routes import auth

app = FastAPI()

# CORS settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SECRET_KEY", "lFqm4oNge6YDWfGi8gvDXWJSJkTXeaRrgxOey4k9zHg"))

app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SECRET_KEY", "lFqm4oNge6YDWfGi8gvDXWJSJkTXeaRrgxOey4k9zHg"),
    session_cookie="oauth_session",
    max_age=1800,
    same_site="lax",
    https_only=False
)
# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")


# Set up Jinja2 templates
templates = Jinja2Templates(directory="src/app/templates")

# Include routes
app.include_router(auth.router)
