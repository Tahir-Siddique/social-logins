from unittest.mock import AsyncMock, patch
from fastapi.responses import RedirectResponse
import pytest
from fastapi import HTTPException, status
from starlette.datastructures import URL
from src.app.services.oauth import OAuthProvider, oauth_service

@pytest.fixture
def mock_request():
    class MockRequest:
        def __init__(self):
            self.session = {}
            self._url_for_called_with = None

        def url_for(self, name: str, **path_params):
            self._url_for_called_with = (name, path_params)
            return URL(f"https://example.com/{name}")

    return MockRequest()

@pytest.mark.asyncio
async def test_initiate_social_login_success(mock_request):
    """
    Test that social login initiation works correctly for a valid provider.
    """
    provider = OAuthProvider.GOOGLE
    redirect_path = "/custom-redirect"

    response: RedirectResponse = await oauth_service.initiate_social_login(provider, mock_request, redirect_path)

    assert "oauth_state" in mock_request.session
    assert mock_request.session["redirect_path"] == redirect_path
    assert response.status_code == 302


@pytest.mark.asyncio
async def test_handle_oauth_callback_invalid_state(mock_request):
    """
    Test that handling OAuth callback raises an error if the state parameter is invalid.
    """
    mock_request.session["oauth_state"] = "valid_state"
    mock_request.query_params = {"state": "invalid_state"}
    provider = OAuthProvider.GOOGLE

    with pytest.raises(HTTPException) as exc_info:
        await oauth_service.handle_oauth_callback(provider, mock_request)

    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert exc_info.value.detail == "Invalid state parameter."

@pytest.mark.asyncio
async def test_handle_oauth_callback_success(mock_request):
    """
    Test that handling OAuth callback works correctly for a valid state and provider.
    """
    # Set up mock request data
    mock_request.session["oauth_state"] = "valid_state"
    mock_request.query_params = {"state": "valid_state"}
    provider = OAuthProvider.GOOGLE

    # Patch methods to mock their behavior
    with patch.object(oauth_service, "get_token", new=AsyncMock(return_value={"access_token": "mock_token"})):
        with patch.object(oauth_service, "fetch_user_data", new=AsyncMock(return_value={"id": "12345", "email": "test@example.com"})):
            
            response = await oauth_service.handle_oauth_callback(provider, mock_request)

            # Assertions
            assert mock_request.session["user"] == {"id": "12345", "email": "test@example.com"}
            assert response.status_code == status.HTTP_307_TEMPORARY_REDIRECT
            assert response.headers["Location"] == "/success"