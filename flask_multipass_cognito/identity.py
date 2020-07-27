from flask_multipass.providers.authlib import AuthlibIdentityProvider
from flask_multipass.data import IdentityInfo
from flask_multipass.group import Group
from flask_multipass.exceptions import GroupRetrievalFailed

from indico.core.logger import Logger

import boto3
from boto3.session import Session as Boto3Session
from botocore.exceptions import ClientError as BotocoreClientError


def _convert_user_attributes(user):
    identity_data = dict()
    identity_data['cognito:username'] = user['Username']
    identity_data['username'] = user['Username']
    identity_data['enabled'] = user['Enabled']
    identity_data['status'] = user['UserStatus']
    for attribute in user['Attributes']:
        if attribute['Name'] == 'email_verified':
            identity_data['email_verified'] = attribute['Value'] == 'true'
        elif attribute['Name'] == 'phone_number_verified':
            identity_data['phone_number_verified'] = attribute['Value'] == 'true'
        else:
            identity_data[attribute['Name']] = attribute['Value']
    return identity_data


def _get_confirmed_identity_data(user):
    if user['Enabled'] is True and \
       user['UserStatus'] == 'CONFIRMED':
        return _convert_user_attributes(user)
    else:
        return None


class CognitoGroup(Group):
    """Group for Amazon Cognito"""

    #: If it is possible to get the list of members of a group.
    supports_member_list = True

    @property
    def cognito_client(self):
        return self.provider.cognito_client

    @property
    def user_pool_id(self):
        return self.provider.user_pool_id

    def get_members(self):
        page_iterator = self.cognito_client.get_paginator('list_users_in_group').paginate(
            UserPoolId=self.user_pool_id,
            GroupName=self.name
        )
        identities = list()
        for response in page_iterator:
            for user in response['Users']:
                identity_data = _get_confirmed_identity_data(user)
                if identity_data is not None:
                    identities.append(IdentityInfo(self.provider, identifier=identity_data['sub'], **identity_data))
        return identities

    def has_member(self, identifier):
        identity_data = self.provider._query_single_user_by_sub(identifier)
        if identity_data is None:
            raise GroupRetrievalFailed(
                "The user with sub={} does not exist or is not confirmed or not enabled".format(identifier)
            )
        page_iterator = self.cognito_client.get_paginator('admin_list_groups_for_user').paginate(
            UserPoolId=self.user_pool_id,
            Username=identity_data['username']
        )
        for response in page_iterator:
            for group in response['Group']:
                if group['GroupName'] == self.name:
                    return True
        return False


class CognitoIdentityProvider(AuthlibIdentityProvider):
    """Provides identity information of Amazon Cognito user using Authlib

    The entrypoint of this provider is ``cognito``

    This extends ``AuthlibIdentityProvider`` with additional capabilities provided by
    Amazon Cognito User Pool API.
    """

    #: If the provider supports getting identity information based from
    #: an identifier
    supports_get = True
    # Cognito User Pool API (ListUsers action) does not support a criteria
    # with multiple conditions.
    # In theory this could be implemented by querying for each condition
    # and apply an intersection on the result sets, but this would be inefficient.
    #: If the provider supports searching identities
    supports_search = False
    #: If the provider also provides groups and membership information
    supports_groups = True
    #: If the provider supports getting the list of groups an identity belongs to
    supports_get_identity_groups = True
    #: The class that represents groups from this provider. Must be a
    #: subclass of :class:`.Group`
    group_class = CognitoGroup

    def __init__(self, *args, **kwargs):
        super(CognitoIdentityProvider, self).__init__(*args, **kwargs)
        # force using `sub` as the id_field?
        # self.id_field = 'sub'
        self.logger = Logger.get('cognito')
        self.user_pool_id = self.settings['user_pool_id']
        boto3_session_kwargs = self.settings.get('boto3_session_kwargs', None)
        if boto3_session_kwargs is not None:
            self.cognito_client = Boto3Session(**boto3_session_kwargs).client('cognito-idp')
        else:
            self.cognito_client = boto3.client('cognito-idp')

    def get_identity_from_auth(self, auth_info):
        identityInfo = super(CognitoIdentityProvider, self).get_identity_from_auth(auth_info)
        self.logger.info('got_identity_from_auth {} from {}'.format(identityInfo, auth_info))
        return identityInfo

    def _query_single_user_by_sub(self, sub):
        page_iterator = self.cognito_client.get_paginator('list_users').paginate(
            UserPoolId=self.user_pool_id,
            Filter="sub = \"{}\"".format(sub)
        )
        for response in page_iterator:
            for user in response['Users']:
                identity_data = _get_confirmed_identity_data(user)
                if identity_data is not None:
                    if identity_data['sub'] == sub:
                        return identity_data
        return None

    def get_identity(self, identifier):
        identity_data = self._query_single_user_by_sub(identifier)
        if identity_data is None:
            return None
        else:
            return IdentityInfo(self, identifier=identity_data['sub'], **identity_data)

    def get_identity_groups(self, sub):
        identity_data = self._query_single_user_by_sub(sub)
        if identity_data is None:
            raise GroupRetrievalFailed(
                "The user with sub={} does not exist or is not confirmed or not enabled".format(sub)
            )
        page_iterator = self.cognito_client.get_paginator('admin_list_groups_for_user').paginate(
            UserPoolId=self.user_pool_id,
            Username=identity_data['username']
        )
        groups = list()
        for response in page_iterator:
            groups.extend([self.group_class(self, group['GroupName'])
                           for group in response['Groups']])
        return groups

    def get_group(self, name):
        try:
            response = self.cognito_client.get_group(
                GroupName=name,
                UserPoolId=self.user_pool_id
            )
            return self.group_class(self, response['Group']['GroupName'])
        except BotocoreClientError as error:
            if error.response['Error']['Code'] == 'ResourceNotFoundException':
                return None
            else:
                raise error

    def search_groups(self, name, exact=False):
        page_iterator = self.cognito_client.get_paginator('list_groups').paginate(
            UserPoolId=self.user_pool_id
        )
        group_names = list()
        for response in page_iterator:
            group_names.extend([group['GroupName'] for group in response['Groups']])
        if exact:
            return [self.group_class(self, group_name) for group_name in group_names if name == group_name]
        else:
            return [self.group_class(self, group_name) for group_name in group_names if name in group_name]

