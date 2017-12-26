import requests


class AuthenticationError(Exception):
    pass


# A simple bot that can authenticate and perform GET and POST requests
class Bot:

    def __init__(self, username, password, api_id, api_secret, user_agent):
        self.usr = username
        self.pwd = password
        self.id = api_id
        self.sec = api_secret
        self.headers = {'User-Agent': user_agent}

    def post(self, url, **kwargs):
        return requests.post(url, headers=self.headers, **kwargs)

    def get(self, url, **kwargs):
        r = requests.get(url, headers=self.headers, **kwargs)
        return r

    def auth(self):
        auth = requests.auth.HTTPBasicAuth(self.id, self.sec)
        data = {
            'grant_type': 'password',
            'username': self.usr,
            'password': self.pwd
        }
        resp = self.post(
            'https://www.reddit.com/api/v1/access_token',
            auth=auth,
            data=data
        )
        token = resp.json().get('access_token')

        if token is None:
            raise AuthenticationError(f'Could not authenticate: {resp.json()}')

        self.headers['Authorization'] = f'bearer {token}'
