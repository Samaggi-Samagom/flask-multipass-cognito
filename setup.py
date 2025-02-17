from setuptools import setup, find_packages


setup(
    name='Flask-Multipass-Cognito',
    version='0.1.1',
    url='https://github.com/Samaggi-Samagom/flask-multipass-cognito',
    description='A Flask Multipass Authentication and Identity providers for Amazon Cognito',
    author='Samaggi Samagom',
    author_email='cto@samaggisamagom.com',
    packages=find_packages(),
    install_requires=[
        'Flask-Multipass[authlib]>=0.3',
        'boto3'
    ],
    entry_points={
        'flask_multipass.auth_providers': {
            'cognito = flask_multipass_cognito.auth:CognitoAuthProvider'
        },
        'flask_multipass.identity_providers': {
            'cognito = flask_multipass_cognito.identity:CognitoIdentityProvider'
        }
    }
)
