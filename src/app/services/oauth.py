import os
import logging
from authlib.integrations.starlette_client import OAuth
from enum import Enum
from typing import Optional, Dict, Any
from fastapi import Request, HTTPException, status
from fastapi.responses import RedirectResponse
import httpx
from src.config import settings

# Initialize logger for the module
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

class OAuthProvider(str, Enum):
    """
    Enum class to represent supported OAuth providers.
    Values:
        - GOOGLE: Represents Google OAuth provider
        - FACEBOOK: Represents Facebook OAuth provider
        - LINKEDIN: Represents LinkedIn OAuth provider
    """
    GOOGLE = "google"
    FACEBOOK = "facebook"
    LINKEDIN = "linkedin"

class OAuthService:
    """
    Class to handle OAuth operations, including client configuration,
    initiating login, handling callbacks, and fetching user data.
    """
    def __init__(self):
        self.oauth = OAuth()
        self.clients = self._initialize_clients()
        logger.info("OAuth clients initialized successfully.")

    def _initialize_clients(self) -> Dict[str, Any]:
        """
        Initialize OAuth clients for supported providers.
        Returns:
            Dict[str, Any]: A dictionary mapping provider names to OAuth clients.
        """
        logger.debug("Initializing OAuth clients.")
        return {
            OAuthProvider.GOOGLE: self._create_google_client(),
            OAuthProvider.FACEBOOK: self._create_facebook_client(),
            OAuthProvider.LINKEDIN: self._create_linkedin_client()
        }

    def _create_google_client(self):
        logger.debug("Creating Google OAuth client.")
        return self.oauth.register(
            name="google",
            client_id=settings.GOOGLE_CLIENT_ID,
            client_secret=settings.GOOGLE_CLIENT_SECRET,
            server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
            client_kwargs={"scope": "openid email profile"}
        )

    def _create_facebook_client(self):
        logger.debug("Creating Facebook OAuth client.")
        return self.oauth.register(
            name="facebook",
            client_id=settings.FACEBOOK_CLIENT_ID,
            client_secret=settings.FACEBOOK_CLIENT_SECRET,
            access_token_url="https://graph.facebook.com/oauth/access_token",
            authorize_url="https://www.facebook.com/dialog/oauth",
            api_base_url="https://graph.facebook.com/v12.0/",
            client_kwargs={"scope": "email public_profile"}
        )

    def _create_linkedin_client(self):
        logger.debug("Creating LinkedIn OAuth client.")
        return self.oauth.register(
            name="linkedin",
            client_id=settings.LINKEDIN_CLIENT_ID,
            client_secret=settings.LINKEDIN_CLIENT_SECRET,
            access_token_url="https://www.linkedin.com/oauth/v2/accessToken",
            authorize_url="https://www.linkedin.com/oauth/v2/authorization",
            api_base_url="https://api.linkedin.com/v2/",
            client_kwargs={"scope": "openid profile email"}
        )

    async def initiate_social_login(self, provider: OAuthProvider, request: Request, redirect_path: Optional[str] = None):
        """
        Start the social login process by redirecting to the provider's authorization page.

        Args:
            provider (OAuthProvider): The OAuth provider.
            request (Request): The incoming HTTP request object.
            redirect_path (Optional[str]): Path to redirect after successful login.

        Returns:
            RedirectResponse: Redirects to the provider's authorization URL.

        Raises:
            HTTPException: If the provider is unsupported or an OAuth error occurs.
        """
        oauth_client = self.clients.get(provider.value)
        if not oauth_client:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unsupported provider: {provider}")

        if redirect_path:
            request.session["redirect_path"] = redirect_path

        redirect_uri = str(request.url_for("auth_callback", provider=provider.value))
        state = os.urandom(16).hex()
        request.session["oauth_state"] = state

        logger.info(f"Initiating login with provider: {provider}")
        return await oauth_client.authorize_redirect(request, redirect_uri, state=state)
    
    async def get_token(self, request: Request, provider: OAuthProvider, oauth_client: OAuth):

        if provider == OAuthProvider.LINKEDIN:
            authorization_code = request.query_params.get("code")
            redirect_uri = str(request.url_for("auth_callback", provider=provider.value))
            token_data = {
                "grant_type": "authorization_code",
                "code": authorization_code,
                "redirect_uri": redirect_uri,
                "client_id": settings.LINKEDIN_CLIENT_ID,
                "client_secret": settings.LINKEDIN_CLIENT_SECRET,
            }

            async with httpx.AsyncClient() as client:
                token_response = await client.post("https://www.linkedin.com/oauth/v2/accessToken", data=token_data)
                if token_response.status_code != 200:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Failed to fetch access token: {token_response.text}"
                    )
                return token_response.json()
        else:
            return await oauth_client.authorize_access_token(request)

    async def handle_oauth_callback(self, provider: OAuthProvider, request: Request):
        """
        Handle the OAuth callback and fetch user data.

        Args:
            provider (OAuthProvider): The OAuth provider.
            request (Request): The incoming HTTP request object.

        Returns:
            RedirectResponse: Redirects to the success page if login is successful, otherwise to the failure page.

        Raises:
            HTTPException: If the state parameter is invalid or an error occurs during user data fetching.
        """
        stored_state = request.session.get("oauth_state")
        received_state = request.query_params.get("state")
        if not stored_state or stored_state != received_state:
            logger.warning("Invalid state parameter during OAuth callback.")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid state parameter.")

        request.session.pop("oauth_state", None)

        oauth_client: OAuth = self.clients.get(provider.value)
        if not oauth_client:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid provider")
        
        token = await self.get_token(request, provider, oauth_client)
        user_data = await self.fetch_user_data(oauth_client, token)

        if not user_data:
            logger.error("Failed to fetch user data.")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to fetch user data.")

        request.session["user"] = user_data
        redirect_path = request.session.pop("redirect_path", "/success")
        logger.info(f"User authenticated successfully with provider: {provider}")
        return RedirectResponse(redirect_path)

    async def fetch_user_data(self, oauth_client: Any, token: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Fetch user data from the specified OAuth provider using the provided token.

        Args:
            oauth_client (Any): The OAuth client instance.
            token (Dict[str, Any]): The access token obtained from the provider.

        Returns:
            Optional[Dict[str, Any]]: User data if successfully fetched, otherwise None.
        """
        try:
            logger.info(f"Fetching user data from provider: {oauth_client.name}")
            if oauth_client.name == OAuthProvider.LINKEDIN.value:
                response = await oauth_client.get("https://api.linkedin.com/v2/userinfo", token=token)
            elif oauth_client.name == OAuthProvider.FACEBOOK.value:
                response = await oauth_client.get(
                    "https://graph.facebook.com/v12.0/me?fields=id,name,email,picture", token=token
                )
            else:  # Google
                response = await oauth_client.get("https://www.googleapis.com/oauth2/v1/userinfo", token=token)

            if response.status_code == 200:
                logger.debug("User data fetched successfully.")
                return response.json()
            else:
                logger.error(f"Failed to fetch user data: {response.status_code} {response.text}")
                return None
        except Exception as e:
            logger.exception(f"Error fetching user data: {str(e)}")
            return None

oauth_service = OAuthService()
