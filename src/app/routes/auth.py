import logging
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from typing import Optional
from src.app.services.oauth import OAuthProvider, oauth_service

# Initialize the FastAPI router and configure Jinja2 templates directory
router = APIRouter()
templates = Jinja2Templates(directory="src/app/templates")

# Set up logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """
    Display the index page. If the user is logged in, their data is shown.

    Args:
        request (Request): The incoming HTTP request object.

    Returns:
        HTMLResponse: Renders the index page with user information (if available).
    """
    user_data = request.session.get("user")
    return templates.TemplateResponse("index.html", {"request": request, "user": user_data})

@router.get("/auth/{provider}")
async def social_login(provider: OAuthProvider, request: Request, redirect_path: Optional[str] = None):
    """
    Start the OAuth login process by redirecting to the provider's authorization page.

    Args:
        provider (OAuthProvider): The selected OAuth provider (Google, Facebook, LinkedIn).
        request (Request): The incoming HTTP request object.
        redirect_path (Optional[str]): Path to redirect after successful login.

    Returns:
        URL: Redirects to the provider's OAuth authorization page.

    Raises:
        HTTPException: If the provider is unsupported or an OAuth error occurs.
    """
    try:
        return await oauth_service.initiate_social_login(provider, request, redirect_path)
    except HTTPException as e:
        logger.error(f"Error during social login: {e.detail}")
        raise

@router.get("/auth/{provider}/callback")
async def auth_callback(provider: OAuthProvider, request: Request):
    """
    Handle the callback from the OAuth provider and fetch user data.

    Args:
        provider (OAuthProvider): The selected OAuth provider.
        request (Request): The incoming HTTP request object.

    Returns:
        RedirectResponse: Redirects to the success page if login is successful, otherwise to the failure page.

    Raises:
        HTTPException: If the state parameter is invalid or the provider is unsupported.
    """
    try:
        return await oauth_service.handle_oauth_callback(provider, request)
    except HTTPException as e:
        logger.error(f"Error during OAuth callback: {e.detail}")
        return RedirectResponse(request.url_for("failure"))

@router.get("/success", response_class=HTMLResponse)
async def success(request: Request):
    """
    Display the success page after successful login.

    Args:
        request (Request): The incoming HTTP request object.

    Returns:
        HTMLResponse: Renders the success page with user information.
        RedirectResponse: Redirects to the failure page if user data is not found.
    """
    user_data = request.session.get("user")
    if not user_data:
        return RedirectResponse("/failure")
    return templates.TemplateResponse("success.html", {"request": request, "user": user_data})

@router.get("/failure", response_class=HTMLResponse)
async def failure(request: Request):
    """
    Display the failure page if login fails.

    Args:
        request (Request): The incoming HTTP request object.

    Returns:
        HTMLResponse: Renders the failure page.
    """
    return templates.TemplateResponse("failure.html", {"request": request})

@router.get("/logout")
async def logout(request: Request):
    """
    Log out the user by clearing session data.

    Args:
        request (Request): The incoming HTTP request object.

    Returns:
        RedirectResponse: Redirects to the homepage after logging out.
    """
    request.session.clear()
    logger.info("User logged out successfully.")
    return RedirectResponse("/")
