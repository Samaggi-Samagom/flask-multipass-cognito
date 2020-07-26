from flask_multipass.providers.authlib import AuthlibIdentityProvider
from indico.core.logger import Logger


class CognitoIdentityProvider(AuthlibIdentityProvider):
    """Provides identity information of Amazon Cognito user using Authlib

    This extends ``AuthlibIdentityProvider`` with additional capabilities provided by
    Amazon Cognito User Pool API.
    """

    #: If the provider supports getting identity information based from
    #: an identifier
    supports_get = False

    def __init__(self, *args, **kwargs):
        super(CognitoIdentityProvider, self).__init__(*args, **kwargs)
        self.aws_profile = self.settings.setdefault('aws_profile', 'default')
        self.logger = Logger.get('cognito')

    def get_identity_from_auth(self, auth_info):
        identityInfo = super(CognitoIdentityProvider, self).get_identity_from_auth(auth_info)
        self.logger.info('got {} from {}'.format(identityInfo, auth_info))
        return identityInfo
