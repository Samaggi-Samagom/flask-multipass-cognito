from flask_multipass.providers.authlib import AuthlibAuthProvider
from flask import request
from werkzeug.urls import url_encode


class CognitoAuthProvider(AuthlibAuthProvider):
    """Provide authentication using Amazon Cognito's implementation of OpenID Connect

    This provider mainly inherit the OIDC capability from Flask Multipass and include addtional
    support for non-standard logout mechanism of Amazon Cognito

    The type name to instantiate this provider is ``cognito``

    For support settings please see
    <https://github.com/indico/flask-multipass/blob/v0.3.dev5/flask_multipass/providers/authlib.py#L49>

    Additional settings for logout endpoint:

    - ``logout_endpoint_uri``: the absolute Cognito LOGOUT endpoint of your Cogntio User Pool,
                               see https://docs.aws.amazon.com/cognito/latest/developerguide/logout-endpoint.html

    - ``registered_logout_uri``: the sign-out uri registered for your client app
                                 (the ``logout_uri`` request parameter in the endpoint)
    """

    def process_logout(self, return_url):
        logout_uri = self.settings.get('logout_endpoint_uri', None)
        if logout_uri is not None:
            return_uri = self.settings.get('registered_logout_uri', request.url_root)
            query = url_encode({'logout_uri': return_uri, 'client_id': self.authlib_client.client_id})
            return redirect(logout_uri + '?' + query)
